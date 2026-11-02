//! Source admission: a connecting address must exactly match a current address
//! of an allowed host. Hosts are resolved again for every connection.

use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

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

/// Reports whether `remote` matches a current address of any host in `hosts`.
/// Empty `hosts` admits nobody; failed or slow lookups are skipped. IPv4-mapped
/// `IPv6` addresses compare equal to their `IPv4` form.
pub async fn admitted(resolver: &dyn Resolver, hosts: &[String], remote: IpAddr) -> bool {
    let remote = remote.to_canonical();
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
