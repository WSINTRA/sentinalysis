//! systemd/journal service tracking — implemented, not yet wired in.
//!
//! Unit discovery ([`discoverer`]), `systemctl` status polling
//! ([`monitor`]), and journalctl tailing ([`journalctl`]) are built and
//! unit-tested, but nothing outside this module references them yet.
//! They are the planned foundation for a "System Services" data source
//! (see `VirtualHostSource::SystemdService` and `JournalctlConfig`).

pub mod discoverer;
pub mod journalctl;
pub mod monitor;
