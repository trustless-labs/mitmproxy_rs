mod mitmproxy_ipc;
pub use mitmproxy_ipc::*;

use crate::intercept_conf;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

impl TryFrom<&Address> for SocketAddr {
    type Error = anyhow::Error;

    fn try_from(address: &Address) -> Result<Self, Self::Error> {
        let port = u16::try_from(address.port)?;
        let (host, scope) = address
            .host
            .split_once('%')
            .map_or((address.host.as_str(), None), |(host, scope)| {
                (host, Some(scope))
            });
        let ip = IpAddr::from_str(host)?;
        match (SocketAddr::new(ip, port), scope) {
            (SocketAddr::V6(mut addr), Some(scope)) => {
                if let Ok(index) = scope.parse::<u32>() {
                    addr.set_scope_id(index);
                    Ok(SocketAddr::V6(addr))
                } else {
                    (address.host.as_str(), port)
                        .to_socket_addrs()?
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("IPv6 scope did not resolve"))
                }
            }
            (addr, None) => Ok(addr),
            (_, Some(_)) => anyhow::bail!("IPv4 addresses cannot have a scope"),
        }
    }
}
impl From<SocketAddr> for Address {
    fn from(val: SocketAddr) -> Self {
        Address {
            host: match val {
                SocketAddr::V6(addr) if addr.scope_id() != 0 => {
                    format!("{}%{}", addr.ip(), addr.scope_id())
                }
                _ => val.ip().to_string(),
            },
            port: val.port() as u32,
        }
    }
}

impl From<intercept_conf::InterceptConf> for InterceptConf {
    fn from(conf: intercept_conf::InterceptConf) -> Self {
        InterceptConf {
            actions: conf.actions(),
        }
    }
}

impl TryFrom<InterceptConf> for intercept_conf::InterceptConf {
    type Error = anyhow::Error;

    fn try_from(conf: InterceptConf) -> Result<Self, Self::Error> {
        intercept_conf::InterceptConf::try_from(conf.actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socketaddr_from_address() {
        let a = Address {
            host: "fe80::f0ff:88ff:febc:3df5".to_string(),
            port: 8080,
        };
        assert!(SocketAddr::try_from(&a).is_ok());

        let b = Address {
            host: "invalid".to_string(),
            port: 8080,
        };
        assert!(SocketAddr::try_from(&b).is_err());

        let c = Address {
            host: "fe80::f0ff:88ff:febc:3df5%3".to_string(),
            port: 8080,
        };
        assert!(SocketAddr::try_from(&c).is_ok());
        assert_ne!(
            SocketAddr::try_from(&a).unwrap(),
            SocketAddr::try_from(&c).unwrap()
        );
        assert_eq!(
            Address::from(SocketAddr::try_from(&c).unwrap()).host,
            c.host
        );
    }
}
