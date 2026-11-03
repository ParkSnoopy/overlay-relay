//! Source admission: a connecting address must exactly match a current address
//! of an allowed host. Hosts are resolved again for every connection.

use std::{fmt::Debug, future::Future, io, net::IpAddr, pin::Pin, time::Duration};

use tokio::time::timeout;

/// Deadline for one host lookup during admission.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Boxed future returned by [`Resolver::resolve`].
pub type LookupFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;

/// Resolves allowed host names to their current addresses.
pub trait Resolver: Debug + Send + Sync {
    /// Returns the addresses `host` currently resolves to.
    ///
    /// # Errors
    /// Returns an I/O error when the name cannot be resolved.
    fn resolve<'a>(&'a self, host: &'a str) -> LookupFuture<'a>;
}

/// The operating system resolver used in production.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> LookupFuture<'a> {
        Box::pin(lookup(host))
    }
}

async fn lookup(host: &str) -> io::Result<Vec<IpAddr>> {
    let addresses = tokio::net::lookup_host((host, 0)).await?;
    Ok(addresses.map(|address| address.ip()).collect())
}

/// Reports whether `address` is loopback, private or link-local.
const fn is_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Reports whether `remote` may connect.
///
/// With `hosts` it must match a current address of one of them; failed or slow
/// lookups are skipped. Without `hosts` any loopback, private or link-local
/// source is admitted, which is every peer on the container network.
/// IPv4-mapped `IPv6` addresses compare equal to their `IPv4` form.
pub async fn admitted(resolver: &dyn Resolver, hosts: &[String], remote: IpAddr) -> bool {
    let remote = remote.to_canonical();
    if hosts.is_empty() {
        return is_local(remote);
    }
    for host in hosts {
        let Ok(Ok(addresses)) = timeout(LOOKUP_TIMEOUT, resolver.resolve(host)).await else {
            continue;
        };
        if addresses
            .iter()
            .any(|address| address.to_canonical() == remote)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{SystemResolver, admitted};

    async fn admitted_without_hosts(text: &str) -> bool {
        let address: IpAddr = text.parse().unwrap_or_else(|_| IpAddr::from([0, 0, 0, 0]));
        admitted(&SystemResolver, &[], address).await
    }

    #[tokio::test]
    async fn without_hosts_only_local_sources_are_admitted() {
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "172.18.0.5",
            "192.168.1.9",
            "169.254.1.1",
            "fd00::5",
            "fe80::1",
            "::1",
            "::ffff:172.18.0.5",
        ] {
            assert!(
                admitted_without_hosts(local).await,
                "{local} must be admitted"
            );
        }
        for public in [
            "8.8.8.8",
            "93.184.216.34",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(
                !admitted_without_hosts(public).await,
                "{public} must be refused"
            );
        }
    }
}
