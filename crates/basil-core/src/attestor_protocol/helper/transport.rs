// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Broker-only `SOCK_SEQPACKET` transport for the measurement helper.
//!
//! `SOCK_SEQPACKET` gives connection-oriented, record-preserving datagrams:
//! one request record maps to exactly one `recvmsg` and its ancillary
//! `SCM_RIGHTS` payload, so descriptor association is unambiguous and both
//! kernel truncation flags (`MSG_TRUNC`, `MSG_CTRUNC`) are surfaced to the
//! service for fail-closed rejection.
//!
//! The transport is deliberately synchronous and serial: the helper is a tiny
//! root-owned service with exactly one authorized client (the broker), and a
//! blocking accept/serve loop keeps the privileged code path small.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Instant;

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
};
use thiserror::Error;

use super::wire::MAX_RESPONSE_BYTES;

/// Maximum descriptors for which ancillary space is reserved on receive.
///
/// A valid request carries exactly one descriptor; reserving room for a few
/// more lets the service distinguish a surplus-descriptor request (typed
/// rejection) from kernel ancillary truncation (also a typed rejection).
pub const MAX_RECEIVED_DESCRIPTORS: usize = 4;

/// Typed transport failure.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The endpoint parent directory failed its trust checks.
    #[error("helper endpoint parent directory is not trustworthy")]
    UntrustedParent,
    /// The endpoint path is occupied by a non-socket object.
    #[error("helper endpoint path is occupied by a non-socket object")]
    PathOccupied,
    /// The endpoint path has no parent directory or is not absolute-safe.
    #[error("helper endpoint path is invalid")]
    InvalidPath,
    /// The caller's deadline elapsed before the peer was ready.
    #[error("helper transport deadline exceeded")]
    DeadlineExceeded,
    /// An underlying socket or filesystem operation failed.
    #[error("helper transport I/O failure: {0}")]
    Io(#[from] std::io::Error),
}

impl From<rustix::io::Errno> for TransportError {
    fn from(errno: rustix::io::Errno) -> Self {
        Self::Io(errno.into())
    }
}

/// Set a `0o077` process umask so nothing the helper creates is ever group
/// or other accessible before its explicit chmod.
///
/// The umask is process-global; the helper binary calls this once at startup
/// before binding its endpoint.
pub fn set_restrictive_umask() {
    let _previous = rustix::process::umask(Mode::from_bits_truncate(0o077));
}

/// Bind-time options for the helper endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelperEndpointOptions {
    /// Exact owner UID required for the endpoint's parent directory.
    pub required_parent_owner_uid: u32,
    /// Mode bits applied to the bound socket (for example `0o660`).
    pub socket_mode: u32,
}

/// A bound helper endpoint listener.
#[derive(Debug)]
pub struct HelperListener {
    fd: OwnedFd,
}

/// One accepted (or connected) helper transport connection.
#[derive(Debug)]
pub struct HelperConnection {
    fd: OwnedFd,
}

/// One received request datagram with its descriptors and kernel flags.
#[derive(Debug)]
pub struct ReceivedDatagram {
    /// Datagram payload bytes (possibly clipped when `oversized`).
    pub bytes: Vec<u8>,
    /// Descriptors carried by `SCM_RIGHTS` ancillary data.
    pub descriptors: Vec<OwnedFd>,
    /// The kernel reported `MSG_TRUNC`: the datagram exceeded the bound.
    pub oversized: bool,
    /// The kernel reported `MSG_CTRUNC`: ancillary data was dropped.
    pub ancillary_truncated: bool,
}

impl HelperListener {
    /// Bind the single shared helper endpoint.
    ///
    /// The parent directory is opened without following symlinks and must be
    /// owned by `options.required_parent_owner_uid` with no group or other
    /// write bit. A stale leftover socket at the path is unlinked; any other
    /// object at the path rejects. The bound socket is chmodded to
    /// `options.socket_mode` before `listen`, so the endpoint is never
    /// observable with wider permissions (callers should also run with a
    /// restrictive umask).
    ///
    /// The `_lockdown` witness makes the ordered lockdown contract
    /// (`basil-rslz`) a compile-time property: the helper endpoint cannot be
    /// created unless [`crate::attestor_protocol::engage`] has already returned
    /// a [`LockdownGuard`], i.e. the allowlist is loaded, the process is
    /// non-dumpable, and the thread-synchronized seccomp filters are installed
    /// and verified.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] on trust-check or socket failures.
    pub fn bind(
        path: &Path,
        options: &HelperEndpointOptions,
        _lockdown: &super::super::lockdown::LockdownGuard,
    ) -> Result<Self, TransportError> {
        let parent = path.parent().ok_or(TransportError::InvalidPath)?;
        let name = path.file_name().ok_or(TransportError::InvalidPath)?;
        let parent_fd = rustix::fs::open(
            parent,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
            Mode::empty(),
        )?;
        let parent_stat = rustix::fs::fstat(&parent_fd)?;
        let group_or_other_write = 0o022;
        if parent_stat.st_uid != options.required_parent_owner_uid
            || (parent_stat.st_mode & group_or_other_write) != 0
        {
            return Err(TransportError::UntrustedParent);
        }

        // Remove only a verified stale socket; never any other object.
        match rustix::fs::statat(&parent_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => {
                if FileType::from_raw_mode(stat.st_mode) != FileType::Socket {
                    return Err(TransportError::PathOccupied);
                }
                rustix::fs::unlinkat(&parent_fd, name, AtFlags::empty())?;
            }
            Err(rustix::io::Errno::NOENT) => {}
            Err(errno) => return Err(errno.into()),
        }

        let fd = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        let address = SocketAddrUnix::new(path)?;
        rustix::net::bind(&fd, &address)?;
        rustix::fs::chmodat(
            &parent_fd,
            name,
            Mode::from_bits_truncate(options.socket_mode),
            AtFlags::empty(),
        )?;
        rustix::net::listen(&fd, 8)?;
        Ok(Self { fd })
    }

    /// Accept one connection, blocking until a client arrives.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] when `accept` fails.
    pub fn accept(&self) -> Result<HelperConnection, TransportError> {
        let fd = rustix::net::accept_with(&self.fd, SocketFlags::CLOEXEC)?;
        Ok(HelperConnection { fd })
    }
}

impl HelperConnection {
    /// Connect to a helper endpoint (broker/conformance-test side).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] when the endpoint is absent or refuses.
    pub fn connect(path: &Path) -> Result<Self, TransportError> {
        let fd = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        let address = SocketAddrUnix::new(path)?;
        rustix::net::connect(&fd, &address)?;
        Ok(Self { fd })
    }

    /// Build a connected pair (conformance tests).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] when `socketpair` fails.
    pub fn pair() -> Result<(Self, Self), TransportError> {
        let (a, b) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        Ok((Self { fd: a }, Self { fd: b }))
    }

    /// Receive one datagram of at most `max_bytes` payload bytes.
    ///
    /// Returns `Ok(None)` on orderly end-of-stream. Kernel truncation is
    /// reported through the returned flags rather than as an error so the
    /// service can answer with a typed rejection.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] when `recvmsg` fails.
    pub fn recv(&self, max_bytes: usize) -> Result<Option<ReceivedDatagram>, TransportError> {
        self.recv_with_flags(max_bytes, RecvFlags::CMSG_CLOEXEC)
    }

    fn recv_with_flags(
        &self,
        max_bytes: usize,
        flags: RecvFlags,
    ) -> Result<Option<ReceivedDatagram>, TransportError> {
        let mut buffer = vec![0u8; max_bytes];
        let mut space = [std::mem::MaybeUninit::uninit();
            rustix::cmsg_space!(ScmRights(MAX_RECEIVED_DESCRIPTORS))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let mut iov = [std::io::IoSliceMut::new(&mut buffer)];
        let message = rustix::net::recvmsg(&self.fd, &mut iov, &mut ancillary, flags)?;
        let mut descriptors = Vec::new();
        for received in ancillary.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = received {
                descriptors.extend(fds);
            }
        }
        let oversized = message.flags.contains(ReturnFlags::TRUNC);
        let ancillary_truncated = message.flags.contains(ReturnFlags::CTRUNC);
        if message.bytes == 0 && descriptors.is_empty() && !oversized && !ancillary_truncated {
            return Ok(None);
        }
        buffer.truncate(message.bytes.min(max_bytes));
        Ok(Some(ReceivedDatagram {
            bytes: buffer,
            descriptors,
            oversized,
            ancillary_truncated,
        }))
    }

    /// Send one datagram with optional `SCM_RIGHTS` descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] when `sendmsg` fails or the payload is
    /// not sent as one record.
    pub fn send(&self, bytes: &[u8], descriptors: &[BorrowedFd<'_>]) -> Result<(), TransportError> {
        self.send_with_flags(bytes, descriptors, SendFlags::NOSIGNAL)
    }

    fn send_with_flags(
        &self,
        bytes: &[u8],
        descriptors: &[BorrowedFd<'_>],
        flags: SendFlags,
    ) -> Result<(), TransportError> {
        let mut space = [std::mem::MaybeUninit::uninit();
            rustix::cmsg_space!(ScmRights(MAX_RECEIVED_DESCRIPTORS))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if !descriptors.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(descriptors))
        {
            return Err(TransportError::Io(std::io::Error::other(
                "ancillary descriptor space exhausted",
            )));
        }
        let iov = [std::io::IoSlice::new(bytes)];
        let sent = rustix::net::sendmsg(&self.fd, &iov, &mut ancillary, flags)?;
        if sent != bytes.len() {
            return Err(TransportError::Io(std::io::Error::other(
                "short seqpacket send",
            )));
        }
        Ok(())
    }

    /// Send one datagram with optional `SCM_RIGHTS` descriptors, waiting no
    /// longer than `deadline` for the peer to accept it.
    ///
    /// Poll-then-nonblocking-write: the descriptor itself stays blocking (the
    /// helper's serial serve loop depends on that), but this path never
    /// sleeps inside `sendmsg`, so a peer that stops reading cannot block the
    /// caller past its deadline.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::DeadlineExceeded`] when the deadline elapses
    /// first, or [`TransportError::Io`] when `poll`/`sendmsg` fail.
    pub fn send_by(
        &self,
        bytes: &[u8],
        descriptors: &[BorrowedFd<'_>],
        deadline: Instant,
    ) -> Result<(), TransportError> {
        loop {
            self.wait_ready(PollFlags::OUT, deadline)?;
            match self.send_with_flags(
                bytes,
                descriptors,
                SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
            ) {
                Err(TransportError::Io(error))
                    if error.kind() == std::io::ErrorKind::WouldBlock => {}
                outcome => return outcome,
            }
        }
    }

    /// Receive one bounded response datagram (broker/conformance-test side).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Io`] when `recvmsg` fails.
    pub fn recv_response(&self) -> Result<Option<ReceivedDatagram>, TransportError> {
        self.recv(MAX_RESPONSE_BYTES)
    }

    /// Receive one bounded response datagram, waiting no longer than
    /// `deadline` (broker side).
    ///
    /// Poll-then-nonblocking-read, so a helper that wedges with its endpoint
    /// still open (as opposed to crashing, which surfaces as end-of-stream)
    /// cannot block the caller past its deadline.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::DeadlineExceeded`] when the deadline elapses
    /// first, or [`TransportError::Io`] when `poll`/`recvmsg` fail.
    pub fn recv_response_by(
        &self,
        deadline: Instant,
    ) -> Result<Option<ReceivedDatagram>, TransportError> {
        loop {
            self.wait_ready(PollFlags::IN, deadline)?;
            match self.recv_with_flags(
                MAX_RESPONSE_BYTES,
                RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT,
            ) {
                Err(TransportError::Io(error))
                    if error.kind() == std::io::ErrorKind::WouldBlock => {}
                outcome => return outcome,
            }
        }
    }

    /// Poll until the descriptor reports `ready` (or an error/hangup state,
    /// which the following nonblocking I/O call surfaces), failing closed at
    /// `deadline`.
    fn wait_ready(&self, ready: PollFlags, deadline: Instant) -> Result<(), TransportError> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::DeadlineExceeded);
            }
            let timeout = Timespec {
                tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
                tv_nsec: i64::from(remaining.subsec_nanos()),
            };
            let mut fds = [PollFd::new(&self.fd, ready)];
            match rustix::event::poll(&mut fds, Some(&timeout)) {
                Ok(0) | Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {
                    // Timed out or interrupted: the next iteration recomputes
                    // the remaining window and fails closed once it is empty.
                }
                Ok(_) => return Ok(()),
                Err(errno) => return Err(errno.into()),
            }
        }
    }
}

impl AsFd for HelperConnection {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd as _;

    use std::num::NonZeroU64;

    use super::super::super::lockdown::{LockdownGuard, LockdownProfileId, LockdownProfileKind};
    use super::super::wire::MAX_REQUEST_BYTES;
    use super::*;

    /// A helper lockdown witness for bind tests, constructed without engaging
    /// seccomp (engaging inside the shared cargo-test process would filter or
    /// kill it).
    fn test_guard() -> LockdownGuard {
        let profile = LockdownProfileId::new(
            "basil-measure-helper-lockdown-g1",
            NonZeroU64::new(1).expect("nonzero"),
            LockdownProfileKind::MeasureHelperV1,
        )
        .expect("valid helper test profile");
        LockdownGuard::for_test(profile)
    }

    #[test]
    fn round_trips_one_datagram_with_one_descriptor() {
        let (client, server) = HelperConnection::pair().expect("pair");
        let (stream_a, _stream_b) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("stream pair");
        client.send(b"hello", &[stream_a.as_fd()]).expect("send");
        let received = server
            .recv(MAX_REQUEST_BYTES)
            .expect("recv")
            .expect("datagram");
        assert_eq!(received.bytes, b"hello");
        assert_eq!(received.descriptors.len(), 1);
        assert!(!received.oversized);
        assert!(!received.ancillary_truncated);
    }

    #[test]
    fn flags_oversized_datagrams() {
        let (client, server) = HelperConnection::pair().expect("pair");
        let big = vec![0xAAu8; MAX_REQUEST_BYTES + 100];
        client.send(&big, &[]).expect("send");
        let received = server
            .recv(MAX_REQUEST_BYTES)
            .expect("recv")
            .expect("datagram");
        assert!(received.oversized);
        assert_eq!(received.bytes.len(), MAX_REQUEST_BYTES);
    }

    #[test]
    fn flags_ancillary_truncation() {
        let (client, server) = HelperConnection::pair().expect("pair");
        // Twelve descriptors exceed the reserved space for four (the space
        // macro pads for alignment, so a small excess can still fit): CTRUNC.
        let pairs: Vec<_> = (0..6)
            .map(|_| {
                rustix::net::socketpair(
                    AddressFamily::UNIX,
                    SocketType::STREAM,
                    SocketFlags::CLOEXEC,
                    None,
                )
                .expect("stream pair")
            })
            .collect();
        let fds: Vec<_> = pairs
            .iter()
            .flat_map(|(a, b)| [a.as_fd(), b.as_fd()])
            .collect();
        // Send with our own larger buffer, bypassing `send`'s bound.
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(12))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(&fds)));
        let iov = [std::io::IoSlice::new(b"x")];
        rustix::net::sendmsg(client.as_fd(), &iov, &mut ancillary, SendFlags::NOSIGNAL)
            .expect("sendmsg");
        let received = server
            .recv(MAX_REQUEST_BYTES)
            .expect("recv")
            .expect("datagram");
        assert!(received.ancillary_truncated);
    }

    #[test]
    fn reports_end_of_stream_as_none() {
        let (client, server) = HelperConnection::pair().expect("pair");
        drop(client);
        assert!(server.recv(MAX_REQUEST_BYTES).expect("recv").is_none());
    }

    #[test]
    fn binds_accepts_and_survives_restart_with_a_stale_socket() {
        let base = std::env::temp_dir().join(format!(
            "basil-helper-endpoint-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).expect("create dir");
        let path = base.join("control.sock");
        let options = HelperEndpointOptions {
            required_parent_owner_uid: rustix::process::getuid().as_raw(),
            socket_mode: 0o600,
        };

        let listener = HelperListener::bind(&path, &options, &test_guard()).expect("bind");
        let client = HelperConnection::connect(&path).expect("connect");
        let server = listener.accept().expect("accept");
        client.send(b"ping", &[]).expect("send");
        assert_eq!(
            server
                .recv(MAX_REQUEST_BYTES)
                .expect("recv")
                .expect("datagram")
                .bytes,
            b"ping"
        );

        // Outage: with the listener gone, connect fails. Serialized against
        // child-spawning tests: a mid-`fork` child briefly holds a copy of
        // the listening descriptor, which would keep the socket accepting.
        {
            let _spawn_guard = super::super::CHILD_SPAWN_TEST_LOCK.lock().unwrap();
            drop(listener);
            drop(server);
            assert!(HelperConnection::connect(&path).is_err());
        }

        // Restart: the stale socket file is unlinked and rebinding works.
        let listener = HelperListener::bind(&path, &options, &test_guard()).expect("rebind");
        let client2 = HelperConnection::connect(&path).expect("reconnect");
        let server2 = listener.accept().expect("accept");
        client2.send(b"pong", &[]).expect("send");
        assert_eq!(
            server2
                .recv(MAX_REQUEST_BYTES)
                .expect("recv")
                .expect("datagram")
                .bytes,
            b"pong"
        );
        drop(client);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn refuses_a_non_socket_object_at_the_endpoint_path() {
        let base =
            std::env::temp_dir().join(format!("basil-helper-occupied-{}", std::process::id()));
        std::fs::create_dir_all(&base).expect("create dir");
        let path = base.join("control.sock");
        std::fs::write(&path, b"not a socket").expect("write");
        let options = HelperEndpointOptions {
            required_parent_owner_uid: rustix::process::getuid().as_raw(),
            socket_mode: 0o600,
        };
        assert!(matches!(
            HelperListener::bind(&path, &options, &test_guard()),
            Err(TransportError::PathOccupied)
        ));
        let _ = std::fs::remove_dir_all(&base);
    }
}
