// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Claim structs, message roles, and parameterized claim validation.
//!
//! The wire codec for claims (CWT map in header 15 plus the basil private
//! labels) lives in the codec seam; this module owns the typed claim set and
//! its temporal/audience/role checks.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::error::ClaimsError;
use crate::hash::RequestHash;
use crate::label;
use crate::types::{KeyId, MessageId, ResponseSubject, Subject, UnixTime};

/// The claim set carried in a protected header (CWT map, header 15, plus the
/// basil private labels).
///
/// One struct for every role; [`MessageRole`] validators enforce which fields
/// must / must not be present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// CWT `iss` (1).
    pub issuer: Option<Subject>,
    /// CWT `aud` (3).
    pub audience: Option<Subject>,
    /// CWT `exp` (4); when absent the effective expiry is
    /// `iat + default_ttl` from [`ValidationParams`].
    pub expires_at: Option<UnixTime>,
    /// CWT `iat` (6). Required.
    pub issued_at: UnixTime,
    /// CWT `cti` (7). Required; sender-unique inside the replay window.
    pub message_id: MessageId,
    /// `-70003`: must equal the outer `kid` on signed/sealed messages.
    pub sender_key_id: Option<KeyId>,
    /// `-70004`: the key a response must be sealed to (requests).
    pub response_key_id: Option<KeyId>,
    /// `-70005`: where to deliver the response (requests, optional).
    pub response_subject: Option<ResponseSubject>,
    /// `-70001`: the request message id this message answers (responses).
    pub in_reply_to: Option<MessageId>,
    /// `-70002`: SHA3-256 of the complete request bytes (responses).
    pub request_hash: Option<RequestHash>,
}

/// Additional protected header values carried outside the CWT claim map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtectedHeaders {
    /// `-70006`: compact trusted-signer certificate JWTs for the signer `kid`.
    pub signer_certificates_jwt: Vec<String>,
}

impl ProtectedHeaders {
    /// Return true when no optional protected headers are present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.signer_certificates_jwt.is_empty()
    }
}

/// Which claim shape a validator demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRole {
    /// Requires `sender_key_id` + `response_key_id`; forbids
    /// `in_reply_to`/`request_hash`.
    Request,
    /// Requires `in_reply_to` + `request_hash`; forbids
    /// `response_key_id`/`response_subject`.
    Response,
    /// Peer message (demo, edgebox): requires `sender_key_id`; forbids the
    /// request/response correlation labels.
    Peer,
}

/// Parameterized validation bounds. The broker feeds its `[invocation]`
/// config; edgebox feeds its own. `now` is injected, never sampled
/// internally: a broker-free crate does not own time policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationParams {
    /// The verifier's current time.
    pub now: UnixTime,
    /// Maximum tolerated clock skew in either direction.
    pub max_clock_skew: Duration,
    /// Cap on an explicit `exp - iat` span.
    pub max_ttl: Duration,
    /// Effective TTL when `exp` is absent.
    pub default_ttl: Duration,
    /// Empty = no audience restriction configured. When non-empty, a present
    /// `aud` must match; messages without `aud` are accepted.
    pub allowed_audiences: BTreeSet<Subject>,
    /// The claim shape to demand.
    pub role: MessageRole,
}

/// Saturating conversion from a `Duration` to whole seconds as `i64`.
#[allow(clippy::cast_possible_wrap)]
const fn secs_i64(d: Duration) -> i64 {
    let s = d.as_secs();
    if s > i64::MAX as u64 {
        i64::MAX
    } else {
        s as i64
    }
}

impl Claims {
    /// Validate this claim set against `params`: clock-skew on `iat`,
    /// effective expiry (`iat + default_ttl` when `exp` is absent), the
    /// `max_ttl` cap on an explicit span, the audience allow-list, and the
    /// role shape.
    ///
    /// # Errors
    /// The first [`ClaimsError`] encountered, in the order above.
    pub fn validate(&self, params: &ValidationParams) -> Result<(), ClaimsError> {
        let skew = secs_i64(params.max_clock_skew);
        let iat = self.issued_at.0;
        let now = params.now.0;

        if iat > now.saturating_add(skew) {
            return Err(ClaimsError::IssuedInFuture);
        }

        let effective_exp = match self.expires_at {
            Some(UnixTime(exp)) => {
                let span = exp.saturating_sub(iat);
                if span <= 0 {
                    return Err(ClaimsError::NonPositiveTtl);
                }
                if span > secs_i64(params.max_ttl) {
                    return Err(ClaimsError::TtlTooLong { seconds: span });
                }
                exp
            }
            None => iat.saturating_add(secs_i64(params.default_ttl)),
        };
        if now > effective_exp.saturating_add(skew) {
            return Err(ClaimsError::Expired);
        }

        if !params.allowed_audiences.is_empty()
            && let Some(aud) = &self.audience
            && !params.allowed_audiences.contains(aud)
        {
            return Err(ClaimsError::AudienceRejected);
        }

        self.validate_role(params.role)
    }

    /// Validate only the role shape (which basil labels must / must not be
    /// present). Builders run this before sealing.
    ///
    /// # Errors
    /// [`ClaimsError::MissingClaim`] / [`ClaimsError::ForbiddenClaim`] with
    /// the offending label.
    pub fn validate_role(&self, role: MessageRole) -> Result<(), ClaimsError> {
        let require = |present: bool, l: i64| {
            if present {
                Ok(())
            } else {
                Err(ClaimsError::MissingClaim { label: l })
            }
        };
        let forbid = |present: bool, l: i64| {
            if present {
                Err(ClaimsError::ForbiddenClaim { label: l })
            } else {
                Ok(())
            }
        };
        match role {
            MessageRole::Request => {
                require(self.sender_key_id.is_some(), label::SENDER_KEY_ID)?;
                require(self.response_key_id.is_some(), label::RESPONSE_KEY_ID)?;
                forbid(self.in_reply_to.is_some(), label::IN_REPLY_TO)?;
                forbid(self.request_hash.is_some(), label::REQUEST_HASH)
            }
            MessageRole::Response => {
                require(self.in_reply_to.is_some(), label::IN_REPLY_TO)?;
                require(self.request_hash.is_some(), label::REQUEST_HASH)?;
                forbid(self.response_key_id.is_some(), label::RESPONSE_KEY_ID)?;
                forbid(self.response_subject.is_some(), label::RESPONSE_SUBJECT)
            }
            MessageRole::Peer => {
                require(self.sender_key_id.is_some(), label::SENDER_KEY_ID)?;
                forbid(self.in_reply_to.is_some(), label::IN_REPLY_TO)?;
                forbid(self.request_hash.is_some(), label::REQUEST_HASH)?;
                forbid(self.response_key_id.is_some(), label::RESPONSE_KEY_ID)?;
                forbid(self.response_subject.is_some(), label::RESPONSE_SUBJECT)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn base_claims() -> Claims {
        Claims {
            issuer: None,
            audience: None,
            expires_at: None,
            issued_at: UnixTime(1_000),
            message_id: MessageId::from_bytes(vec![1, 2, 3]).unwrap(),
            sender_key_id: Some(KeyId::from_text("alice").unwrap()),
            response_key_id: None,
            response_subject: None,
            in_reply_to: None,
            request_hash: None,
        }
    }

    fn params(now: i64) -> ValidationParams {
        ValidationParams {
            now: UnixTime(now),
            max_clock_skew: Duration::from_secs(5),
            max_ttl: Duration::from_mins(5),
            default_ttl: Duration::from_mins(1),
            allowed_audiences: BTreeSet::new(),
            role: MessageRole::Peer,
        }
    }

    #[test]
    fn accepts_fresh_message() {
        assert_eq!(base_claims().validate(&params(1_010)), Ok(()));
    }

    #[test]
    fn rejects_future_iat_beyond_skew() {
        assert_eq!(
            base_claims().validate(&params(990)),
            Err(ClaimsError::IssuedInFuture)
        );
    }

    #[test]
    fn accepts_future_iat_within_skew() {
        assert_eq!(base_claims().validate(&params(996)), Ok(()));
    }

    #[test]
    fn rejects_expired_default_ttl() {
        // iat 1000 + default 60 + skew 5 => latest acceptable now is 1065.
        assert_eq!(base_claims().validate(&params(1_065)), Ok(()));
        assert_eq!(
            base_claims().validate(&params(1_066)),
            Err(ClaimsError::Expired)
        );
    }

    #[test]
    fn explicit_exp_overrides_default() {
        let mut c = base_claims();
        c.expires_at = Some(UnixTime(1_100));
        assert_eq!(c.validate(&params(1_105)), Ok(()));
        assert_eq!(c.validate(&params(1_106)), Err(ClaimsError::Expired));
    }

    #[test]
    fn rejects_over_long_explicit_ttl() {
        let mut c = base_claims();
        c.expires_at = Some(UnixTime(1_000 + 301));
        assert_eq!(
            c.validate(&params(1_010)),
            Err(ClaimsError::TtlTooLong { seconds: 301 })
        );
    }

    #[test]
    fn rejects_non_positive_ttl() {
        let mut c = base_claims();
        c.expires_at = Some(UnixTime(1_000));
        assert_eq!(c.validate(&params(1_010)), Err(ClaimsError::NonPositiveTtl));
    }

    #[test]
    fn audience_rules() {
        let mut p = params(1_010);
        p.allowed_audiences
            .insert(Subject::new("svc-a".to_string()).unwrap());
        // Absent aud accepted even with a non-empty allow-list.
        assert_eq!(base_claims().validate(&p), Ok(()));
        // Matching aud accepted.
        let mut c = base_claims();
        c.audience = Some(Subject::new("svc-a".to_string()).unwrap());
        assert_eq!(c.validate(&p), Ok(()));
        // Non-matching aud rejected.
        c.audience = Some(Subject::new("svc-b".to_string()).unwrap());
        assert_eq!(c.validate(&p), Err(ClaimsError::AudienceRejected));
        // Empty allow-list = no restriction.
        assert_eq!(c.validate(&params(1_010)), Ok(()));
    }

    #[test]
    fn request_role_shape() {
        let mut c = base_claims();
        assert_eq!(
            c.validate_role(MessageRole::Request),
            Err(ClaimsError::MissingClaim {
                label: label::RESPONSE_KEY_ID
            })
        );
        c.response_key_id = Some(KeyId::from_text("bob").unwrap());
        assert_eq!(c.validate_role(MessageRole::Request), Ok(()));
        c.request_hash = Some(RequestHash([0; 32]));
        assert_eq!(
            c.validate_role(MessageRole::Request),
            Err(ClaimsError::ForbiddenClaim {
                label: label::REQUEST_HASH
            })
        );
    }

    #[test]
    fn response_role_shape() {
        let mut c = base_claims();
        assert_eq!(
            c.validate_role(MessageRole::Response),
            Err(ClaimsError::MissingClaim {
                label: label::IN_REPLY_TO
            })
        );
        c.in_reply_to = Some(MessageId::from_bytes(vec![9]).unwrap());
        c.request_hash = Some(RequestHash([0; 32]));
        assert_eq!(c.validate_role(MessageRole::Response), Ok(()));
        c.response_subject = Some(ResponseSubject::new("inbox".to_string()).unwrap());
        assert_eq!(
            c.validate_role(MessageRole::Response),
            Err(ClaimsError::ForbiddenClaim {
                label: label::RESPONSE_SUBJECT
            })
        );
    }

    #[test]
    fn peer_role_shape() {
        let mut c = base_claims();
        assert_eq!(c.validate_role(MessageRole::Peer), Ok(()));
        c.sender_key_id = None;
        assert_eq!(
            c.validate_role(MessageRole::Peer),
            Err(ClaimsError::MissingClaim {
                label: label::SENDER_KEY_ID
            })
        );
    }
}
