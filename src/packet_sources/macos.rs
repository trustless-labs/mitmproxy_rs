use std::net::{Ipv4Addr, SocketAddr};

use crate::messages::{ConnectionIdGenerator, TransportCommand, TransportEvent, TunnelInfo};

use crate::intercept_conf::InterceptConf;
use crate::ipc;
use crate::ipc::{NewFlow, TcpFlow, UdpFlow};
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};
use crate::shutdown;
use anyhow::{Context, Result, bail};
use futures_util::SinkExt;
use futures_util::StreamExt;

use prost::Message;
use prost::bytes::Buf;
use prost::bytes::Bytes;
use prost::bytes::BytesMut;

use std::process::Stdio;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::network::udp::{UdpHandler, UdpPacket};
use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub struct MacosConf;

async fn start_redirector(listener_addr: String) -> Result<()> {
    log::debug!("Starting redirector app...");
    let redirector_process =
        Command::new("/Applications/Mitmproxy Redirector.app/Contents/MacOS/Mitmproxy Redirector")
            .arg(listener_addr)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to launch macos-redirector app.")?;

    let output = redirector_process.wait_with_output().await?;
    if !output.stdout.is_empty() {
        log::info!(
            "[macos-redirector] {}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    if !output.stderr.is_empty() {
        log::error!(
            "[macos-redirector] {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if !output.status.success() {
        bail!(
            "macos-redirector exited with status {:?}",
            output.status.code()
        );
    }
    log::debug!("Redirector app exited successfully.");
    Ok(())
}

impl PacketSourceConf for MacosConf {
    type Task = MacOsTask;
    type Data = UnboundedSender<InterceptConf>;

    fn name(&self) -> &'static str {
        "macOS proxy"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        _transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: shutdown::Receiver,
    ) -> Result<(Self::Task, Self::Data)> {
        let listener_addr = format!("/tmp/mitmproxy-{}", std::process::id());
        let listener = UnixListener::bind(&listener_addr)?;

        start_redirector(listener_addr).await?;

        log::debug!("Waiting for control channel...");
        // XXX: Saw some hangs here during development, not sure why.
        let control_channel = timeout(Duration::new(5, 0), listener.accept())
            .await
            .context("failed to establish connection to macOS system extension")??
            .0;
        log::debug!("Control channel connected.");

        let (conf_tx, conf_rx) = unbounded_channel();
        Ok((
            MacOsTask {
                control_channel,
                listener,
                connections: JoinSet::new(),
                transport_events_tx,
                conf_rx,
                shutdown,
            },
            conf_tx,
        ))
    }
}

pub struct MacOsTask {
    control_channel: UnixStream,
    listener: UnixListener,
    connections: JoinSet<Result<()>>,
    transport_events_tx: Sender<TransportEvent>,
    conf_rx: UnboundedReceiver<InterceptConf>,
    shutdown: shutdown::Receiver,
}

impl PacketSourceTask for MacOsTask {
    async fn run(mut self) -> Result<()> {
        let mut control_channel = Framed::new(self.control_channel, LengthDelimitedCodec::new());

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.shutdown.recv() => break,
                _ = control_channel.next() => {
                    // No messages expected here at the moment.
                    bail!("macOS System Extension shut down.")
                },
                Some(task) = self.connections.join_next() => {
                    match task {
                        Ok(Ok(())) => (),
                        Ok(Err(e)) => log::error!("Connection task failure: {e:?}"),
                        Err(e) => log::error!("Connection task panic: {e:?}"),
                    }
                },
                l = self.listener.accept() => {
                    match l {
                        Ok((stream, _)) => {
                            let task = ConnectionTask::new(
                                stream,
                                self.transport_events_tx.clone(),
                                self.shutdown.clone(),
                            );
                            self.connections.spawn(task.run());
                        },
                        Err(e) => log::error!("Error accepting connection from macos-redirector: {e}")
                    }
                },
                // pipe through changes to the intercept list
                Some(conf) = self.conf_rx.recv() => {
                    let msg = ipc::InterceptConf::from(conf).encode_to_vec();
                    control_channel.send(Bytes::from(msg)).await.context("Failed to write to control channel")?;
                },
            }
        }

        log::info!("Macos OS proxy task shutting down.");
        Ok(())
    }
}

struct ConnectionTask {
    stream: UnixStream,
    events: Sender<TransportEvent>,
    shutdown: shutdown::Receiver,
}

impl ConnectionTask {
    pub fn new(
        stream: UnixStream,
        events: Sender<TransportEvent>,
        shutdown: shutdown::Receiver,
    ) -> Self {
        Self {
            stream,
            events,
            shutdown,
        }
    }
    async fn run(mut self) -> Result<()> {
        let new_flow = {
            let len = self
                .stream
                .read_u32()
                .await
                .context("Failed to read handshake.")? as usize;
            let mut buf = vec![0; len];
            self.stream
                .read_exact(&mut buf)
                .await
                .context("Failed to read handshake contents.")?;
            NewFlow::decode(buf.as_slice()).context("Invalid handshake IPC")?
        };

        match new_flow {
            NewFlow {
                message: Some(ipc::new_flow::Message::Tcp(tcp_flow)),
            } => self
                .handle_tcp(tcp_flow)
                .await
                .context("failed to handle TCP stream"),
            NewFlow {
                message: Some(ipc::new_flow::Message::Udp(udp_flow)),
            } => self
                .handle_udp(udp_flow)
                .await
                .context("failed to handle UDP stream"),
            _ => bail!("Received invalid IPC message: {new_flow:?}"),
        }
    }

    async fn handle_udp(mut self, flow: UdpFlow) -> Result<()> {
        // For UDP connections, we pass length-delimited protobuf messages over the unix socket
        // in both directions.
        let mut write_buf = BytesMut::new();
        let mut stream = Framed::new(self.stream, LengthDelimitedCodec::new());

        let Some(tun) = flow.tunnel_info else {
            bail!("no tunnel info")
        };
        let local_address = {
            let Some(addr) = &flow.local_address else {
                bail!("no local address")
            };
            SocketAddr::try_from(addr)
                .with_context(|| format!("invalid local_address: {addr:?}"))?
        };
        let (command_tx, mut command_rx) = unbounded_channel();
        let mut handler = UdpHandler::new();
        let mut pending_event = None;
        let mut expiry = tokio::time::interval(Duration::from_secs(5));

        loop {
            tokio::select! {
                _ = self.shutdown.recv() => break,
                _ = expiry.tick() => handler.poll(),
                permit = self.events.reserve(), if pending_event.is_some() => {
                    permit?.send(pending_event.take().unwrap());
                },
                packet = stream.next(), if pending_event.is_none() && handler.packet_queue_len() < 10 => {
                    let Some(packet) = packet else { break };
                    let packet = ipc::UdpPacket::decode(
                        packet.context("IPC read error")?
                    ).context("invalid IPC message")?;
                    let Some(remote) = &packet.remote_address else { bail!("no remote addr") };
                    let dst_addr = SocketAddr::try_from(remote).with_context(|| format!("invalid remote_address: {remote:?}"))?;
                    pending_event = handler.receive_data(
                        UdpPacket {
                            src_addr: local_address,
                            dst_addr,
                            payload: packet.data.to_vec(),
                        },
                        TunnelInfo::LocalRedirector {
                            pid: tun.pid,
                            process_name: tun.process_name.clone(),
                            remote_endpoint: Some((remote.host.clone(), remote.port as u16)),
                        },
                        Some(command_tx.clone()),
                    );
                },
                Some(command) = command_rx.recv() => {
                    if let Some(UdpPacket { payload, src_addr, .. }) = handler.handle_transport_command(command) {
                        let packet = ipc::UdpPacket {
                            data: Bytes::from(payload),
                            remote_address: Some(src_addr.into()),
                        };
                        write_buf.reserve(packet.encoded_len());
                        packet.encode(&mut write_buf)?;
                        stream.send(write_buf.split().freeze()).await.context("failed to send UDP reply")?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_tcp(mut self, flow: TcpFlow) -> Result<()> {
        let mut write_buf = BytesMut::new();
        let mut drain_tx: Option<oneshot::Sender<()>> = None;
        let mut read_tx: Option<(usize, oneshot::Sender<Vec<u8>>)> = None;

        let (command_tx, mut command_rx) = unbounded_channel();

        let remote = flow.remote_address.expect("no remote address");
        let src_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let dst_addr = SocketAddr::try_from(&remote)
            .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let tunnel_info = TunnelInfo::LocalRedirector {
            pid: flow.tunnel_info.as_ref().and_then(|t| t.pid),
            process_name: flow.tunnel_info.and_then(|t| t.process_name),
            remote_endpoint: Some((remote.host, remote.port as u16)),
        };

        self.events
            .send(TransportEvent::ConnectionEstablished {
                connection_id: ConnectionIdGenerator::tcp().next_id(),
                src_addr,
                dst_addr,
                tunnel_info,
                command_tx: Some(command_tx),
            })
            .await?;

        loop {
            tokio::select! {
                _ = self.shutdown.recv() => break,
                Ok(()) = self.stream.writable(), if !write_buf.is_empty() => {
                    // Readiness may be stale, so we must not await here or we would block reads and shutdown.
                    match self.stream.try_write(&write_buf) {
                        Ok(n) => write_buf.advance(n),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(_) => break,  // Client has disconnected.
                    }
                    if write_buf.is_empty()
                        && let Some(tx) = drain_tx.take() {
                            tx.send(()).ok();
                        }
                },
                Ok(()) = self.stream.readable(), if read_tx.is_some() => {
                    let mut data = Vec::with_capacity(read_tx.as_ref().unwrap().0);
                    // Readiness may be stale, so we must not await here or we would block writes and shutdown.
                    match self.stream.try_read_buf(&mut data) {
                        Ok(_) => {},
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Err(e).context("failed to read from socket"),
                    }
                    let (_, tx) = read_tx.take().unwrap();
                    tx.send(data).ok();
                },
                Some(command) = command_rx.recv() => {
                    match command {
                        TransportCommand::ReadData(_, n, tx) => {
                            assert!(read_tx.is_none());
                            read_tx = Some((n as usize, tx));
                        },
                        TransportCommand::WriteData(_, data) => {
                            write_buf.extend_from_slice(data.as_slice());
                        },
                        TransportCommand::DrainWriter(_, tx) => {
                            assert!(drain_tx.is_none());
                            if write_buf.is_empty() {
                                tx.send(()).ok();
                            } else {
                                drain_tx = Some(tx);
                            }
                        },
                        TransportCommand::CloseConnection(_, half_close) => {
                            self.stream.flush().await.ok(); // supposedly this is a no-op on unix sockets.
                            self.stream.shutdown().await.ok();
                            if !half_close {
                                break;
                            }
                        }
                    }
                },
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn spawn_tcp_connection() -> (
        UnixStream,
        tokio::task::JoinHandle<Result<()>>,
        UnboundedSender<TransportCommand>,
        crate::messages::ConnectionId,
        tokio::sync::watch::Sender<()>,
    ) {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = shutdown::channel();
        let task = tokio::spawn(ConnectionTask::new(server, events_tx, shutdown_rx).run());

        let handshake = NewFlow {
            message: Some(ipc::new_flow::Message::Tcp(TcpFlow {
                remote_address: Some(ipc::Address {
                    host: "127.0.0.1".into(),
                    port: 443,
                }),
                tunnel_info: None,
            })),
        }
        .encode_to_vec();
        client.write_u32(handshake.len() as u32).await.unwrap();
        client.write_all(&handshake).await.unwrap();

        let Some(TransportEvent::ConnectionEstablished {
            connection_id,
            command_tx: Some(command_tx),
            ..
        }) = events_rx.recv().await
        else {
            panic!("expected TCP connection");
        };
        (client, task, command_tx, connection_id, shutdown_tx)
    }

    async fn spawn_udp_connection(
        capacity: usize,
    ) -> Result<(
        Framed<UnixStream, LengthDelimitedCodec>,
        tokio::task::JoinHandle<Result<()>>,
        tokio::sync::mpsc::Receiver<TransportEvent>,
        tokio::sync::watch::Sender<()>,
        Sender<TransportEvent>,
    )> {
        let (mut client, server) = UnixStream::pair()?;
        let (events_tx, events_rx) = tokio::sync::mpsc::channel(capacity);
        let (shutdown_tx, shutdown_rx) = shutdown::channel();
        let task = tokio::spawn(ConnectionTask::new(server, events_tx.clone(), shutdown_rx).run());
        let handshake = NewFlow {
            message: Some(ipc::new_flow::Message::Udp(UdpFlow {
                local_address: Some(ipc::Address {
                    host: "127.0.0.1".into(),
                    port: 5353,
                }),
                tunnel_info: Some(ipc::TunnelInfo {
                    pid: Some(123),
                    process_name: Some("sender".into()),
                }),
            })),
        }
        .encode_to_vec();
        client.write_u32(handshake.len() as u32).await?;
        client.write_all(&handshake).await?;
        let client = Framed::new(client, LengthDelimitedCodec::new());
        Ok((client, task, events_rx, shutdown_tx, events_tx))
    }

    #[tokio::test]
    async fn udp_full_event_queue_does_not_block_existing_connection() -> Result<()> {
        let (mut client, task, mut events_rx, shutdown_tx, events_tx) =
            spawn_udp_connection(1).await?;
        let packet = Bytes::from(
            ipc::UdpPacket {
                data: Bytes::from_static(b"packet"),
                remote_address: Some(ipc::Address {
                    host: "127.0.0.1".into(),
                    port: 53,
                }),
            }
            .encode_to_vec(),
        );
        client.send(packet.clone()).await?;
        let event = timeout(Duration::from_secs(1), events_rx.recv())
            .await?
            .unwrap();
        let TransportEvent::ConnectionEstablished {
            connection_id,
            command_tx: Some(ref commands),
            ..
        } = event
        else {
            panic!("expected UDP connection");
        };
        let commands = commands.clone();
        events_tx.send(event).await?;
        for _ in 0..2 {
            client.send(packet.clone()).await?;
            let (tx, rx) = oneshot::channel();
            commands.send(TransportCommand::ReadData(connection_id, 1024, tx))?;
            assert_eq!(timeout(Duration::from_secs(1), rx).await??, b"packet");
        }
        drop(shutdown_tx);
        timeout(Duration::from_secs(1), task).await???;
        Ok(())
    }

    #[tokio::test]
    async fn udp_destinations_have_independent_connections() -> Result<()> {
        check_udp_destinations(["10.10.0.219", "100.65.40.14"]).await
    }

    #[tokio::test]
    async fn udp_scoped_destinations_have_independent_connections() -> Result<()> {
        check_udp_destinations(["fe80::1%1", "fe80::1%2"]).await
    }

    async fn check_udp_destinations(destinations: [&str; 2]) -> Result<()> {
        let (mut client, task, mut events_rx, shutdown_tx, _events_tx) =
            spawn_udp_connection(16).await?;
        let mut connections = Vec::new();
        for host in destinations {
            client
                .send(Bytes::from(
                    ipc::UdpPacket {
                        data: Bytes::copy_from_slice(host.as_bytes()),
                        remote_address: Some(ipc::Address {
                            host: host.into(),
                            port: 62941,
                        }),
                    }
                    .encode_to_vec(),
                ))
                .await?;
            let event = timeout(Duration::from_secs(1), events_rx.recv()).await?;
            let Some(TransportEvent::ConnectionEstablished {
                connection_id,
                dst_addr,
                command_tx: Some(commands),
                tunnel_info,
                ..
            }) = event
            else {
                panic!("expected a connection for {host}")
            };
            assert_eq!(dst_addr.port(), 62941);
            assert!(matches!(tunnel_info, TunnelInfo::LocalRedirector {
                pid: Some(123), ref process_name, ref remote_endpoint,
            } if process_name.as_deref() == Some("sender")
                && remote_endpoint == &Some((host.into(), 62941))));
            let (tx, rx) = oneshot::channel();
            commands.send(TransportCommand::ReadData(connection_id, 1024, tx))?;
            assert_eq!(timeout(Duration::from_secs(1), rx).await??, host.as_bytes());
            connections.push((connection_id, commands));
        }
        assert_ne!(connections[0].0, connections[1].0);
        for (index, (id, commands)) in connections.iter().enumerate().rev() {
            commands.send(TransportCommand::WriteData(*id, b"reply".to_vec()))?;
            let reply = timeout(Duration::from_secs(1), client.next())
                .await?
                .unwrap()?;
            let reply = ipc::UdpPacket::decode(reply)?;
            let remote = reply.remote_address.unwrap();
            assert_eq!(remote.host, destinations[index]);
            assert_eq!(remote.port, 62941);
            assert_eq!(reply.data.as_ref(), b"reply");
        }
        connections[0]
            .1
            .send(TransportCommand::CloseConnection(connections[0].0, false))?;
        client
            .send(Bytes::from(
                ipc::UdpPacket {
                    data: Bytes::from_static(b"still open"),
                    remote_address: Some(ipc::Address {
                        host: destinations[1].into(),
                        port: 62941,
                    }),
                }
                .encode_to_vec(),
            ))
            .await?;
        let (tx, rx) = oneshot::channel();
        connections[1]
            .1
            .send(TransportCommand::ReadData(connections[1].0, 1024, tx))?;
        assert_eq!(timeout(Duration::from_secs(1), rx).await??, b"still open");
        drop(shutdown_tx);
        timeout(Duration::from_secs(1), task).await???;
        Ok(())
    }

    #[tokio::test]
    async fn udp_remote_endpoint_keeps_scope() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(16);
        let (_shutdown_tx, shutdown_rx) = shutdown::channel();
        tokio::spawn(ConnectionTask::new(server, events_tx, shutdown_rx).run());

        let handshake = NewFlow {
            message: Some(ipc::new_flow::Message::Udp(UdpFlow {
                local_address: Some(ipc::Address {
                    host: "fe80::2%en0".into(),
                    port: 5353,
                }),
                tunnel_info: Some(ipc::TunnelInfo {
                    pid: None,
                    process_name: None,
                }),
            })),
        }
        .encode_to_vec();
        client.write_u32(handshake.len() as u32).await.unwrap();
        client.write_all(&handshake).await.unwrap();
        let packet = ipc::UdpPacket {
            data: Bytes::from_static(b"query"),
            remote_address: Some(ipc::Address {
                host: "fe80::1%en0".into(),
                port: 53,
            }),
        }
        .encode_to_vec();
        client.write_u32(packet.len() as u32).await.unwrap();
        client.write_all(&packet).await.unwrap();

        let Some(TransportEvent::ConnectionEstablished {
            tunnel_info:
                TunnelInfo::LocalRedirector {
                    remote_endpoint, ..
                },
            ..
        }) = events_rx.recv().await
        else {
            panic!("expected UDP connection");
        };
        assert_eq!(remote_endpoint, Some(("fe80::1%en0".to_string(), 53)));
    }

    #[tokio::test]
    async fn tcp_pending_read_does_not_block_writes() {
        let (mut client, task, commands, id, shutdown_tx) = spawn_tcp_connection().await;

        let (tx, rx) = oneshot::channel();
        commands
            .send(TransportCommand::ReadData(id, 1, tx))
            .unwrap();
        client.write_all(b"a").await.unwrap();
        assert_eq!(rx.await.unwrap(), b"a");

        // The socket may still report stale read readiness here.
        let (tx, rx) = oneshot::channel();
        commands
            .send(TransportCommand::ReadData(id, 1, tx))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
        commands
            .send(TransportCommand::WriteData(id, b"reply".to_vec()))
            .unwrap();
        let mut response = [0; 5];
        timeout(Duration::from_secs(1), client.read_exact(&mut response))
            .await
            .expect("pending read blocked writes")
            .unwrap();
        assert_eq!(&response, b"reply");

        client.write_all(b"b").await.unwrap();
        assert_eq!(rx.await.unwrap(), b"b");
        drop(shutdown_tx);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn tcp_pending_write_does_not_block_reads_or_shutdown() {
        let (mut client, task, commands, id, shutdown_tx) = spawn_tcp_connection().await;

        // The client never reads, so this write cannot complete.
        commands
            .send(TransportCommand::WriteData(id, vec![0; 1024 * 1024]))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
        let (tx, rx) = oneshot::channel();
        commands
            .send(TransportCommand::ReadData(id, 1, tx))
            .unwrap();
        client.write_all(b"a").await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), rx)
                .await
                .expect("pending write blocked reads")
                .unwrap(),
            b"a"
        );

        drop(shutdown_tx);
        timeout(Duration::from_secs(1), task)
            .await
            .expect("pending write blocked shutdown")
            .unwrap()
            .unwrap();
    }
}
