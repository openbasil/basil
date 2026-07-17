// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Fixed, bounded binary records for the measurement-helper protocol.
//!
//! The helper protocol is deliberately not protobuf: every record is a fixed
//! big-endian layout with explicit length prefixes, an exact-length framing
//! rule (trailing bytes reject), and compiled ceilings. A request is at most
//! [`MAX_REQUEST_BYTES`] bytes and a response at most [`MAX_RESPONSE_BYTES`]
//! bytes; both bounds are part of the contract in
//! `docs/attestor-realm-contract/SPEC.md`.
//!
//! Requests never carry a PID, path, digest, unit, or UID. Responses echo the
//! request identity, report the helper-policy identity and generation the
//! helper actually applied, and bind the measured record to the duplicated
//! stream's socket cookie.

use std::num::NonZeroU64;

use thiserror::Error;

use super::ident;

/// Helper protocol version implemented by this module.
pub const HELPER_PROTOCOL_VERSION: u32 = 1;
/// Absolute maximum bytes in one request datagram.
pub const MAX_REQUEST_BYTES: usize = 512;
/// Absolute maximum bytes in one response datagram.
pub const MAX_RESPONSE_BYTES: usize = 4096;
/// Exact bytes in the request nonce.
pub const NONCE_BYTES: usize = 32;

/// Request record magic (`BMH1`).
const REQUEST_MAGIC: [u8; 4] = *b"BMH1";
/// Response record magic (`BMR1`).
const RESPONSE_MAGIC: [u8; 4] = *b"BMR1";
/// Response status byte: measurement succeeded.
const STATUS_MEASURED: u8 = 1;
/// Response status byte: request rejected.
const STATUS_REJECTED: u8 = 2;

/// Typed decode/encode failure for helper protocol records.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum WireError {
    /// The record is shorter than its declared layout.
    #[error("helper record truncated")]
    Truncated,
    /// The record has bytes after its declared layout.
    #[error("helper record has trailing bytes")]
    TrailingBytes,
    /// The record magic is unknown.
    #[error("helper record magic unknown")]
    BadMagic,
    /// The protocol version is not supported.
    #[error("helper protocol version {0} unsupported")]
    UnsupportedProtocol(u32),
    /// A length, generation, or enum field is outside its contract bound.
    #[error("helper record field `{0}` invalid")]
    InvalidField(&'static str),
    /// The encoded record would exceed its compiled ceiling.
    #[error("helper record exceeds its size ceiling")]
    Oversized,
}

/// Disclosure-safe rejection codes carried on the wire.
///
/// Codes are stable contract values; free-text diagnostics never cross the
/// helper boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RejectCode {
    /// The request record failed strict decoding.
    MalformedRequest = 1,
    /// The request protocol version is unsupported.
    UnsupportedProtocol = 2,
    /// The named helper-policy identity/generation pair is not installed.
    PolicyNotInstalled = 3,
    /// The named realm is not present in the installed policy generation.
    RealmNotInstalled = 4,
    /// The request carried no descriptor.
    DescriptorMissing = 5,
    /// The request carried more than one descriptor.
    DescriptorSurplus = 6,
    /// The carried descriptor is not a connected Unix stream socket.
    DescriptorType = 7,
    /// Ancillary data was truncated by the kernel.
    AncillaryTruncated = 8,
    /// Peer credential, cookie, or pidfd derivation failed.
    PeerDerivationFailed = 9,
    /// The derived peer identity does not match the installed expectation.
    PeerIdentityMismatch = 10,
    /// The peer's systemd unit could not be resolved.
    UnitResolutionFailed = 11,
    /// The resolved unit does not equal the installed expected unit.
    UnitMismatch = 12,
    /// A generation-qualifier binding check failed.
    GenerationBinding = 13,
    /// The peer's LSM or lockdown identity does not match the expectation.
    ConfinementMismatch = 14,
    /// The peer executable could not be opened or is not a regular file.
    ExecutableAccess = 15,
    /// The peer exited or changed identity during measurement.
    PeerExited = 16,
    /// An internal helper failure; the request is not at fault.
    Internal = 17,
}

impl RejectCode {
    /// Decode a wire code.
    const fn from_wire(value: u16) -> Option<Self> {
        Some(match value {
            1 => Self::MalformedRequest,
            2 => Self::UnsupportedProtocol,
            3 => Self::PolicyNotInstalled,
            4 => Self::RealmNotInstalled,
            5 => Self::DescriptorMissing,
            6 => Self::DescriptorSurplus,
            7 => Self::DescriptorType,
            8 => Self::AncillaryTruncated,
            9 => Self::PeerDerivationFailed,
            10 => Self::PeerIdentityMismatch,
            11 => Self::UnitResolutionFailed,
            12 => Self::UnitMismatch,
            13 => Self::GenerationBinding,
            14 => Self::ConfinementMismatch,
            15 => Self::ExecutableAccess,
            16 => Self::PeerExited,
            17 => Self::Internal,
            _ => return None,
        })
    }
}

/// One bounded measurement request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementRequest {
    /// Helper protocol version; must be [`HELPER_PROTOCOL_VERSION`].
    pub protocol: u32,
    /// Broker configuration generation at the time of the request.
    pub broker_generation: u64,
    /// Required installed helper-policy generation.
    pub policy_generation: NonZeroU64,
    /// Fresh request nonce echoed verbatim in the response.
    pub nonce: [u8; NONCE_BYTES],
    /// Allowlisted realm name.
    pub realm: String,
    /// Required installed helper-policy identity.
    pub policy_identity: String,
}

impl MeasurementRequest {
    /// Encode this request into its exact wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] when a field violates its contract bound.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.protocol != HELPER_PROTOCOL_VERSION {
            return Err(WireError::UnsupportedProtocol(self.protocol));
        }
        if !ident::is_valid_realm_name(&self.realm) {
            return Err(WireError::InvalidField("realm"));
        }
        if !ident::is_valid_identity(&self.policy_identity) {
            return Err(WireError::InvalidField("policyIdentity"));
        }
        let mut out = Vec::with_capacity(MAX_REQUEST_BYTES);
        out.extend_from_slice(&REQUEST_MAGIC);
        out.extend_from_slice(&self.protocol.to_be_bytes());
        out.extend_from_slice(&self.broker_generation.to_be_bytes());
        out.extend_from_slice(&self.policy_generation.get().to_be_bytes());
        out.extend_from_slice(&self.nonce);
        push_short_string(&mut out, &self.realm)?;
        push_short_string(&mut out, &self.policy_identity)?;
        if out.len() > MAX_REQUEST_BYTES {
            return Err(WireError::Oversized);
        }
        Ok(out)
    }

    /// Strictly decode one request datagram.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] on any truncation, trailing byte, bound, or
    /// charset violation.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(WireError::Oversized);
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != REQUEST_MAGIC {
            return Err(WireError::BadMagic);
        }
        let protocol = reader.u32()?;
        if protocol != HELPER_PROTOCOL_VERSION {
            return Err(WireError::UnsupportedProtocol(protocol));
        }
        let broker_generation = reader.u64()?;
        let policy_generation =
            NonZeroU64::new(reader.u64()?).ok_or(WireError::InvalidField("policyGeneration"))?;
        let nonce = reader.array::<NONCE_BYTES>()?;
        let realm = reader.short_string()?;
        if !ident::is_valid_realm_name(&realm) {
            return Err(WireError::InvalidField("realm"));
        }
        let policy_identity = reader.short_string()?;
        if !ident::is_valid_identity(&policy_identity) {
            return Err(WireError::InvalidField("policyIdentity"));
        }
        reader.finish()?;
        Ok(Self {
            protocol,
            broker_generation,
            policy_generation,
            nonce,
            realm,
            policy_identity,
        })
    }
}

/// The bounded measured record bound to the duplicated stream's cookie.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasuredRecord {
    /// Helper protocol version.
    pub protocol: u32,
    /// Echo of the request's broker generation.
    pub broker_generation: u64,
    /// Echo of the request nonce.
    pub nonce: [u8; NONCE_BYTES],
    /// `SO_COOKIE` of the duplicated attestor control stream.
    pub cookie: u64,
    /// `SO_PEERCRED` peer UID.
    pub peer_uid: u32,
    /// `SO_PEERCRED` peer GID.
    pub peer_gid: u32,
    /// `SO_PEERCRED` peer PID.
    pub peer_pid: u32,
    /// Peer process start time (kernel clock ticks since boot).
    pub peer_start_time: u64,
    /// Device number of the measured executable.
    pub executable_device: u64,
    /// Inode number of the measured executable.
    pub executable_inode: u64,
    /// Echo of the request realm.
    pub realm: String,
    /// Helper-policy identity the helper actually applied.
    pub policy_identity: String,
    /// Helper-policy generation the helper actually applied.
    pub policy_generation: NonZeroU64,
    /// Resolved systemd service unit of the peer.
    pub service_unit: String,
}

/// A disclosure-safe rejection record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectionRecord {
    /// Helper protocol version.
    pub protocol: u32,
    /// Typed rejection code.
    pub code: RejectCode,
    /// Echo of the request's broker generation (zero when undecodable).
    pub broker_generation: u64,
    /// Echo of the request nonce (zeroed when undecodable).
    pub nonce: [u8; NONCE_BYTES],
}

/// One decoded helper response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HelperResponse {
    /// The measurement succeeded; two descriptors accompany the record.
    Measured(MeasuredRecord),
    /// The request was rejected; no descriptors accompany the record.
    Rejected(RejectionRecord),
}

impl MeasuredRecord {
    /// Encode this record into its exact wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] when a field violates its contract bound.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.protocol != HELPER_PROTOCOL_VERSION {
            return Err(WireError::UnsupportedProtocol(self.protocol));
        }
        if !ident::is_valid_realm_name(&self.realm) {
            return Err(WireError::InvalidField("realm"));
        }
        if !ident::is_valid_identity(&self.policy_identity) {
            return Err(WireError::InvalidField("policyIdentity"));
        }
        if !ident::is_valid_service_unit(&self.service_unit) {
            return Err(WireError::InvalidField("serviceUnit"));
        }
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&RESPONSE_MAGIC);
        out.extend_from_slice(&self.protocol.to_be_bytes());
        out.push(STATUS_MEASURED);
        out.extend_from_slice(&self.broker_generation.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.cookie.to_be_bytes());
        out.extend_from_slice(&self.peer_uid.to_be_bytes());
        out.extend_from_slice(&self.peer_gid.to_be_bytes());
        out.extend_from_slice(&self.peer_pid.to_be_bytes());
        out.extend_from_slice(&self.peer_start_time.to_be_bytes());
        out.extend_from_slice(&self.executable_device.to_be_bytes());
        out.extend_from_slice(&self.executable_inode.to_be_bytes());
        push_short_string(&mut out, &self.realm)?;
        push_short_string(&mut out, &self.policy_identity)?;
        out.extend_from_slice(&self.policy_generation.get().to_be_bytes());
        push_short_string(&mut out, &self.service_unit)?;
        if out.len() > MAX_RESPONSE_BYTES {
            return Err(WireError::Oversized);
        }
        Ok(out)
    }
}

impl RejectionRecord {
    /// Encode this rejection into its exact wire bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&RESPONSE_MAGIC);
        out.extend_from_slice(&HELPER_PROTOCOL_VERSION.to_be_bytes());
        out.push(STATUS_REJECTED);
        out.extend_from_slice(&(self.code as u16).to_be_bytes());
        out.extend_from_slice(&self.broker_generation.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }
}

impl HelperResponse {
    /// Strictly decode one response datagram.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] on any truncation, trailing byte, bound, or
    /// charset violation.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(WireError::Oversized);
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != RESPONSE_MAGIC {
            return Err(WireError::BadMagic);
        }
        let protocol = reader.u32()?;
        if protocol != HELPER_PROTOCOL_VERSION {
            return Err(WireError::UnsupportedProtocol(protocol));
        }
        match reader.u8()? {
            STATUS_MEASURED => {
                let broker_generation = reader.u64()?;
                let nonce = reader.array::<NONCE_BYTES>()?;
                let cookie = reader.u64()?;
                let peer_user = reader.u32()?;
                let peer_group = reader.u32()?;
                let peer_process = reader.u32()?;
                let peer_start_time = reader.u64()?;
                let executable_device = reader.u64()?;
                let executable_inode = reader.u64()?;
                let realm = reader.short_string()?;
                if !ident::is_valid_realm_name(&realm) {
                    return Err(WireError::InvalidField("realm"));
                }
                let policy_identity = reader.short_string()?;
                if !ident::is_valid_identity(&policy_identity) {
                    return Err(WireError::InvalidField("policyIdentity"));
                }
                let policy_generation = NonZeroU64::new(reader.u64()?)
                    .ok_or(WireError::InvalidField("policyGeneration"))?;
                let service_unit = reader.short_string()?;
                if !ident::is_valid_service_unit(&service_unit) {
                    return Err(WireError::InvalidField("serviceUnit"));
                }
                reader.finish()?;
                Ok(Self::Measured(MeasuredRecord {
                    protocol,
                    broker_generation,
                    nonce,
                    cookie,
                    peer_uid: peer_user,
                    peer_gid: peer_group,
                    peer_pid: peer_process,
                    peer_start_time,
                    executable_device,
                    executable_inode,
                    realm,
                    policy_identity,
                    policy_generation,
                    service_unit,
                }))
            }
            STATUS_REJECTED => {
                let code =
                    RejectCode::from_wire(reader.u16()?).ok_or(WireError::InvalidField("code"))?;
                let broker_generation = reader.u64()?;
                let nonce = reader.array::<NONCE_BYTES>()?;
                reader.finish()?;
                Ok(Self::Rejected(RejectionRecord {
                    protocol,
                    code,
                    broker_generation,
                    nonce,
                }))
            }
            _ => Err(WireError::InvalidField("status")),
        }
    }
}

/// Append one `u8`-length-prefixed short string.
fn push_short_string(out: &mut Vec<u8>, value: &str) -> Result<(), WireError> {
    let length = u8::try_from(value.len()).map_err(|_| WireError::InvalidField("length"))?;
    if length == 0 {
        return Err(WireError::InvalidField("length"));
    }
    out.push(length);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

/// Bounded, panic-free byte reader.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    const fn take(&mut self, count: usize) -> Result<&'a [u8], WireError> {
        if self.bytes.len() < count {
            return Err(WireError::Truncated);
        }
        let (head, tail) = self.bytes.split_at(count);
        self.bytes = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let slice = self.take(N)?;
        <[u8; N]>::try_from(slice).map_err(|_| WireError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn short_string(&mut self) -> Result<String, WireError> {
        let length = usize::from(self.u8()?);
        if length == 0 {
            return Err(WireError::InvalidField("length"));
        }
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| WireError::InvalidField("utf8"))
    }

    const fn finish(&self) -> Result<(), WireError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> MeasurementRequest {
        MeasurementRequest {
            protocol: HELPER_PROTOCOL_VERSION,
            broker_generation: 42,
            policy_generation: NonZeroU64::MIN,
            nonce: [7u8; NONCE_BYTES],
            realm: "production-docker".to_owned(),
            policy_identity: "basil-measure-policy-g1".to_owned(),
        }
    }

    fn record() -> MeasuredRecord {
        MeasuredRecord {
            protocol: HELPER_PROTOCOL_VERSION,
            broker_generation: 42,
            nonce: [7u8; NONCE_BYTES],
            cookie: 99,
            peer_uid: 992,
            peer_gid: 992,
            peer_pid: 4321,
            peer_start_time: 555,
            executable_device: 3,
            executable_inode: 1_234_567,
            realm: "production-docker".to_owned(),
            policy_identity: "basil-measure-policy-g1".to_owned(),
            policy_generation: NonZeroU64::MIN,
            service_unit: "basil-attestor-production-docker-g1.service".to_owned(),
        }
    }

    #[test]
    fn request_round_trip() {
        let encoded = request().encode().expect("encode");
        assert!(encoded.len() <= MAX_REQUEST_BYTES);
        assert_eq!(
            MeasurementRequest::decode(&encoded).expect("decode"),
            request()
        );
    }

    #[test]
    fn maximal_request_fits_the_ceiling() {
        let mut big = request();
        big.realm = format!("a{}b", "x".repeat(61));
        big.policy_identity = format!("p{}-g1", "y".repeat(123));
        let encoded = big.encode().expect("encode");
        assert!(encoded.len() <= MAX_REQUEST_BYTES);
        assert_eq!(MeasurementRequest::decode(&encoded).expect("decode"), big);
    }

    #[test]
    fn request_rejects_malformed_records() {
        let good = request().encode().expect("encode");
        // Truncation at every boundary.
        for cut in 0..good.len() {
            assert!(MeasurementRequest::decode(good.get(..cut).expect("slice")).is_err());
        }
        // Trailing byte.
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            MeasurementRequest::decode(&trailing),
            Err(WireError::TrailingBytes)
        );
        // Wrong magic.
        let mut magic = good;
        if let Some(first) = magic.first_mut() {
            *first = b'X';
        }
        assert_eq!(MeasurementRequest::decode(&magic), Err(WireError::BadMagic));
        // Oversized datagram.
        let oversized = vec![0u8; MAX_REQUEST_BYTES + 1];
        assert_eq!(
            MeasurementRequest::decode(&oversized),
            Err(WireError::Oversized)
        );
    }

    #[test]
    fn request_rejects_field_violations() {
        let mut wrong_protocol = request();
        wrong_protocol.protocol = 2;
        assert_eq!(
            wrong_protocol.encode(),
            Err(WireError::UnsupportedProtocol(2))
        );

        let mut zero_generation = request().encode().expect("encode");
        // The policy generation occupies bytes 16..24.
        for byte in zero_generation.iter_mut().skip(16).take(8) {
            *byte = 0;
        }
        assert_eq!(
            MeasurementRequest::decode(&zero_generation),
            Err(WireError::InvalidField("policyGeneration"))
        );

        let mut bad_realm = request();
        bad_realm.realm = "UPPER".to_owned();
        assert_eq!(bad_realm.encode(), Err(WireError::InvalidField("realm")));

        let mut bad_identity = request();
        bad_identity.policy_identity = "no way".to_owned();
        assert_eq!(
            bad_identity.encode(),
            Err(WireError::InvalidField("policyIdentity"))
        );
    }

    #[test]
    fn measured_round_trip() {
        let encoded = record().encode().expect("encode");
        assert!(encoded.len() <= MAX_RESPONSE_BYTES);
        match HelperResponse::decode(&encoded).expect("decode") {
            HelperResponse::Measured(decoded) => assert_eq!(decoded, record()),
            HelperResponse::Rejected(_) => panic!("expected measured"),
        }
    }

    #[test]
    fn rejection_round_trip() {
        let rejection = RejectionRecord {
            protocol: HELPER_PROTOCOL_VERSION,
            code: RejectCode::UnitMismatch,
            broker_generation: 42,
            nonce: [9u8; NONCE_BYTES],
        };
        let encoded = rejection.encode();
        assert!(encoded.len() <= MAX_RESPONSE_BYTES);
        match HelperResponse::decode(&encoded).expect("decode") {
            HelperResponse::Rejected(decoded) => assert_eq!(decoded, rejection),
            HelperResponse::Measured(_) => panic!("expected rejection"),
        }
    }

    #[test]
    fn response_rejects_malformed_records() {
        let good = record().encode().expect("encode");
        for cut in 0..good.len() {
            assert!(HelperResponse::decode(good.get(..cut).expect("slice")).is_err());
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            HelperResponse::decode(&trailing),
            Err(WireError::TrailingBytes)
        );
        // Unknown status byte.
        let mut status = good;
        if let Some(byte) = status.get_mut(8) {
            *byte = 9;
        }
        assert_eq!(
            HelperResponse::decode(&status),
            Err(WireError::InvalidField("status"))
        );
        // Unknown rejection code.
        let mut coded = RejectionRecord {
            protocol: HELPER_PROTOCOL_VERSION,
            code: RejectCode::Internal,
            broker_generation: 0,
            nonce: [0u8; NONCE_BYTES],
        }
        .encode();
        if let Some(byte) = coded.get_mut(10) {
            *byte = 200;
        }
        assert_eq!(
            HelperResponse::decode(&coded),
            Err(WireError::InvalidField("code"))
        );
    }
}
