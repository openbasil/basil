// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Envoy Secret Discovery Service adapter.
//!
//! SDS publishes the same X.509-SVID and trust-bundle material as the SPIFFE
//! Workload API.

#![allow(clippy::result_large_err)]

use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::Arc;

use basil_proto::envoy::config::core::v3::DataSource;
use basil_proto::envoy::config::core::v3::data_source::Specifier;
use basil_proto::envoy::extensions::transport_sockets::tls::v3::secret::Type;
use basil_proto::envoy::extensions::transport_sockets::tls::v3::{
    CertificateValidationContext, Secret, TlsCertificate,
};
use basil_proto::envoy::service::discovery::v3::{
    DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
};
use basil_proto::envoy::service::secret::v3::secret_discovery_service_server::SecretDiscoveryService;
use futures::{Stream, StreamExt as _};
use prost::Message as _;
use prost_types::Any;
use tonic::{Code, Request, Response, Status, Streaming};

use crate::actor::{AuthenticatedActor, SubjectResolutionError};
use crate::catalog::policy::Op;
use crate::catalog::{Class, KeyEntry};
use crate::decision::DecisionRecord;
use crate::peer::PeerInfo;
use crate::state::{BrokerState, Generation};
use crate::transport::peer_from_request;

type SdsResult<T> = Result<Response<T>, Status>;
type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

/// Type URL Envoy uses for SDS `Secret` resources.
pub const SECRET_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";

/// Label on an X.509-SVID issuer naming the Envoy TLS certificate resource.
pub const CERTIFICATE_RESOURCE_LABEL: &str = "envoy_sds_certificate_resource";

/// Label on an X.509-SVID issuer naming the Envoy validation-context resource.
pub const VALIDATION_CONTEXT_RESOURCE_LABEL: &str = "envoy_sds_validation_context_resource";

const VERSION_INFO: &str = "basil-sds-v1";
const NONCE: &str = "basil-sds-initial";

/// Envoy SDS v3 service adapter.
#[derive(Debug, Clone)]
pub struct EnvoySdsGrpc {
    state: Arc<BrokerState>,
}

impl EnvoySdsGrpc {
    /// Build an Envoy SDS service adapter.
    #[must_use]
    pub const fn new(state: Arc<BrokerState>) -> Self {
        Self { state }
    }

    async fn discovery_response(
        &self,
        peer: &PeerInfo,
        request: &DiscoveryRequest,
    ) -> Result<DiscoveryResponse, Status> {
        validate_type_url(&request.type_url)?;
        let plans = self.resource_plans(peer, &request.resource_names)?;
        let mut resources = Vec::with_capacity(plans.len());
        for plan in plans {
            resources.push(secret_resource(&self.state, &plan).await?);
        }
        Ok(DiscoveryResponse {
            version_info: VERSION_INFO.to_string(),
            resources,
            canary: false,
            type_url: SECRET_TYPE_URL.to_string(),
            nonce: NONCE.to_string(),
            control_plane: None,
        })
    }

    fn resource_plans(
        &self,
        peer: &PeerInfo,
        requested: &[String],
    ) -> Result<Vec<SdsResourcePlan>, Status> {
        let generation = self.state.load_generation();
        let actor = generation
            .pdp()
            .resolve_local_actor(peer)
            .map_err(|err| sds_resolution_status(&err))?;
        let uid = actor.unix_uid().ok_or_else(|| {
            Status::new(
                Code::Unauthenticated,
                "Envoy SDS requires local peer credentials",
            )
        })?;
        let issuers: Vec<_> = generation
            .catalog()
            .keys
            .iter()
            .filter(|(_, entry)| is_x509_svid_issuer(entry))
            .collect();
        if issuers.is_empty() {
            return Err(Status::new(
                Code::NotFound,
                "no Envoy SDS resource matched the request",
            ));
        }
        let requested = requested_set(requested);
        let mut plans = Vec::new();
        for (key_name, entry) in issuers {
            plans.extend(self.issuer_resource_plans(
                &generation,
                &actor,
                uid,
                key_name,
                entry,
                requested.as_ref(),
            )?);
        }

        if plans.is_empty() {
            return Err(Status::new(
                Code::NotFound,
                "no Envoy SDS resource matched the request",
            ));
        }
        Ok(plans)
    }
}

fn sds_resolution_status(err: &SubjectResolutionError) -> Status {
    match err {
        SubjectResolutionError::MissingPeerCredentials => Status::new(
            Code::Unauthenticated,
            "missing peer credentials for Envoy SDS",
        ),
        SubjectResolutionError::NoSubject { .. }
        | SubjectResolutionError::AmbiguousSubject { .. }
        | SubjectResolutionError::InvalidUnauthenticatedSubject { .. } => {
            Status::new(Code::PermissionDenied, "not authorized for Envoy SDS")
        }
    }
}

#[tonic::async_trait]
impl SecretDiscoveryService for EnvoySdsGrpc {
    type DeltaSecretsStream = BoxStream<DeltaDiscoveryResponse>;
    type StreamSecretsStream = BoxStream<DiscoveryResponse>;

    async fn delta_secrets(
        &self,
        request: Request<Streaming<DeltaDiscoveryRequest>>,
    ) -> SdsResult<Self::DeltaSecretsStream> {
        let _ = request;
        Err(Status::new(
            Code::Unimplemented,
            "DeltaSecrets rotation push is not implemented",
        ))
    }

    async fn stream_secrets(
        &self,
        request: Request<Streaming<DiscoveryRequest>>,
    ) -> SdsResult<Self::StreamSecretsStream> {
        let peer = peer_from_request(&request);
        let mut stream = request.into_inner();
        let Some(initial) = stream.message().await? else {
            return Err(Status::new(
                Code::InvalidArgument,
                "StreamSecrets requires an initial DiscoveryRequest",
            ));
        };
        let response = self.discovery_response(&peer, &initial).await;
        Ok(Response::new(Box::pin(
            futures::stream::once(async move { response }).chain(futures::stream::pending()),
        )))
    }

    async fn fetch_secrets(
        &self,
        request: Request<DiscoveryRequest>,
    ) -> SdsResult<DiscoveryResponse> {
        let peer = peer_from_request(&request);
        Ok(Response::new(
            self.discovery_response(&peer, request.get_ref()).await?,
        ))
    }
}

#[derive(Debug, Clone)]
enum SdsResourcePlan {
    TlsCertificate {
        resource_name: String,
        key_name: String,
        spiffe_id: String,
        ttl_seconds: u64,
    },
    ValidationContext {
        resource_name: String,
        key_name: String,
    },
}

fn requested_set(requested: &[String]) -> Option<BTreeSet<&str>> {
    if requested.is_empty() {
        return None;
    }
    Some(requested.iter().map(String::as_str).collect())
}

impl EnvoySdsGrpc {
    fn issuer_resource_plans(
        &self,
        generation: &Generation,
        actor: &AuthenticatedActor,
        uid: u32,
        key_name: &str,
        entry: &KeyEntry,
        requested: Option<&BTreeSet<&str>>,
    ) -> Result<Vec<SdsResourcePlan>, Status> {
        let mut plans = Vec::with_capacity(2);
        if let Some(resource_name) = selected_label(entry, CERTIFICATE_RESOURCE_LABEL, requested) {
            let decision = generation.pdp().decide(actor, Op::Mint, key_name);
            self.state
                .record_decision(&DecisionRecord::from_actor_decision(
                    generation.id(),
                    actor,
                    Op::Mint,
                    key_name,
                    &decision,
                ));
            if decision.is_deny() {
                return Err(Status::new(
                    Code::PermissionDenied,
                    "not authorized to mint an X.509-SVID for Envoy SDS",
                ));
            }
            let trust_domain = entry.labels.get("trust_domain").ok_or_else(|| {
                Status::new(Code::Internal, "X.509-SVID issuer has no trust_domain")
            })?;
            plans.push(SdsResourcePlan::TlsCertificate {
                resource_name: resource_name.to_string(),
                key_name: key_name.to_string(),
                spiffe_id: templated_spiffe_id(generation, uid, trust_domain)?,
                ttl_seconds: self.state.limits().svid_ttl_secs.max(1),
            });
        }
        // The validation context is deliberately NOT PDP-gated, asymmetric with
        // the `Op::Mint` gate above **by design**: the certificate resource
        // releases a freshly minted *private* key, while the validation context
        // carries only the trust domain's *public* CA bundle, the same bytes
        // the SPIFFE Workload API serves ungated to any socket peer via
        // `FetchX509Bundles` (bundles are public by SPIFFE convention), so a
        // read grant here would add policy friction without hiding anything.
        // The caller must still resolve to a policy subject (checked in
        // `resource_plans` before any plan is built), which is already stricter
        // than the Workload API path.
        if let Some(resource_name) =
            selected_label(entry, VALIDATION_CONTEXT_RESOURCE_LABEL, requested)
        {
            plans.push(SdsResourcePlan::ValidationContext {
                resource_name: resource_name.to_string(),
                key_name: key_name.to_string(),
            });
        }
        Ok(plans)
    }
}

fn selected_label<'a>(
    entry: &'a KeyEntry,
    label: &str,
    requested: Option<&BTreeSet<&str>>,
) -> Option<&'a str> {
    entry
        .labels
        .get(label)
        .filter(|name| requested.is_none_or(|set| set.contains(*name)))
}

async fn secret_resource(state: &BrokerState, plan: &SdsResourcePlan) -> Result<Any, Status> {
    let secret = match plan {
        SdsResourcePlan::TlsCertificate {
            resource_name,
            key_name,
            spiffe_id,
            ttl_seconds,
        } => {
            let mut issued = state
                .manager()
                .issue_x509_svid(key_name, spiffe_id, *ttl_seconds)
                .await
                .map_err(x509_issue_status)?;
            Secret {
                name: resource_name.clone(),
                r#type: Some(Type::TlsCertificate(TlsCertificate {
                    certificate_chain: Some(inline_bytes(issued.cert_chain_der.concat())),
                    // Move (never copy) the leaf key out of its `Zeroizing`
                    // buffer: the proto field is then the only plain copy, and
                    // `TlsCertificate` zeroizes it on drop right after the
                    // `encode_to_vec` below. The encoded `Any` payload also
                    // carries the key but is owned by the discovery response /
                    // tonic after send, out of wiping reach.
                    private_key: Some(inline_bytes(std::mem::take(
                        &mut *issued.leaf_private_key_der,
                    ))),
                })),
            }
        }
        SdsResourcePlan::ValidationContext {
            resource_name,
            key_name,
        } => {
            let routed = state
                .manager()
                .resolve(key_name)
                .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
            let bundle = routed
                .backend
                .x509_bundle(routed.path())
                .await
                .map_err(|e| Status::new(Code::Unavailable, e.to_string()))?;
            Secret {
                name: resource_name.clone(),
                r#type: Some(Type::ValidationContext(CertificateValidationContext {
                    trusted_ca: Some(inline_bytes(bundle.bundle_der.concat())),
                })),
            }
        }
    };
    Ok(Any {
        type_url: SECRET_TYPE_URL.to_string(),
        value: secret.encode_to_vec(),
    })
}

const fn inline_bytes(bytes: Vec<u8>) -> DataSource {
    DataSource {
        specifier: Some(Specifier::InlineBytes(bytes)),
    }
}

fn validate_type_url(type_url: &str) -> Result<(), Status> {
    if type_url.is_empty() || type_url == SECRET_TYPE_URL {
        return Ok(());
    }
    Err(Status::new(
        Code::InvalidArgument,
        "DiscoveryRequest type_url must be Envoy Secret",
    ))
}

fn templated_spiffe_id(
    generation: &Generation,
    uid: u32,
    trust_domain: &str,
) -> Result<String, Status> {
    let segment = generation
        .config()
        .names
        .users
        .get(&uid)
        .map_or_else(|| uid.to_string(), std::string::ToString::to_string);
    let id = format!("spiffe://{trust_domain}/{segment}");
    if is_spiffe_id(&id) {
        Ok(id)
    } else {
        Err(Status::new(
            Code::Internal,
            "templated SPIFFE ID is malformed",
        ))
    }
}

fn is_x509_svid_issuer(entry: &KeyEntry) -> bool {
    entry.class == Class::Asymmetric
        && entry.labels.get("svid_kind") == Some("x509")
        && entry.labels.get("trust_domain").is_some()
}

fn is_spiffe_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("spiffe://") else {
        return false;
    };
    let Some((trust_domain, path)) = rest.split_once('/') else {
        return false;
    };
    is_valid_spiffe_part(trust_domain) && is_valid_spiffe_part(path)
}

fn is_valid_spiffe_part(part: &str) -> bool {
    !part.is_empty() && !part.chars().any(char::is_whitespace)
}

fn x509_issue_status(err: crate::manager::ManagerError) -> Status {
    match err {
        crate::manager::ManagerError::UnknownKey(_) => {
            Status::new(Code::PermissionDenied, "not authorized")
        }
        crate::manager::ManagerError::Unsupported(_)
        | crate::manager::ManagerError::OpNotValidForClass { .. }
        | crate::manager::ManagerError::UnsupportedKeyType { .. } => {
            Status::new(Code::FailedPrecondition, err.to_string())
        }
        crate::manager::ManagerError::Backend(e) => Status::new(Code::Unavailable, e.to_string()),
        crate::manager::ManagerError::UnknownBackend { .. }
        | crate::manager::ManagerError::AlgorithmMismatch { .. }
        | crate::manager::ManagerError::KemAlgorithmMismatch { .. }
        | crate::manager::ManagerError::ValueRotateNeedsSet(_)
        | crate::manager::ManagerError::Sealing(_)
        | crate::manager::ManagerError::Signing(_)
        // A provider-dispatch (ML-DSA software custody) error cannot arise on the
        // X.509 issuance path (a PKI issuer is asymmetric+pki, never ML-DSA);
        // treat it as an internal invariant breach.
        | crate::manager::ManagerError::Provider(_)
        // A COSE unseal-context pin (basil-2rqj) applies only to the sealing
        // UnsealCose path, never X.509 issuance; an internal invariant breach here.
        | crate::manager::ManagerError::UnsealContextNotPermitted(_)
        | crate::manager::ManagerError::MissingPublicPath(_) => {
            Status::new(Code::Internal, err.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use crate::backend::{Backend, BackendError, NewKey, X509Bundle, X509Svid};
    use crate::catalog::loader::load;
    use crate::manager::BackendManager;
    use crate::peer::PeerInfo;
    use async_trait::async_trait;
    use basil_proto::KeyType;
    use basil_proto::envoy::extensions::transport_sockets::tls::v3::Secret;
    use basil_proto::envoy::extensions::transport_sockets::tls::v3::secret::Type;

    const CATALOG: &str = r#"{
      "schema": "catalog",
      "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
      "keys": {
        "spire.x509": {
          "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
          "engine": "pki", "path": "pki/issue/workload",
          "writable": false, "missing": "warn",
          "labels": [
            "svid_kind=x509",
            "trust_domain=example.org",
            "envoy_sds_certificate_resource=default",
            "envoy_sds_validation_context_resource=ROOTCA"
          ],
          "description": "X.509-SVID issuer"
        }
      }
    }"#;

    const POLICY: &str = r#"{
      "schema": "policy",
      "subjects": {
        "test.runner": { "allOf": [ { "kind": "unix", "uid": 42 } ] }
      },
      "roles": { "mint": ["mint"] },
      "rules": [
        { "id": "runner-mint", "subjects": ["test.runner"], "action": ["role:mint"], "target": ["spire.x509"] }
      ],
      "config": {
        "names": { "users": { "42": "test-runner" }, "groups": {} },
        "memberships": { "42": [42] }
      }
    }"#;

    #[derive(Default)]
    struct SdsBackend {
        issued_ids: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Backend for SdsBackend {
        fn kind(&self) -> &'static str {
            "dummy"
        }

        async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError> {
            let _ = key_type;
            Err(BackendError::Unsupported("new_key"))
        }

        async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
            let _ = key_id;
            Err(BackendError::Unsupported("public_key"))
        }

        async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
            let _ = (key_id, message);
            Err(BackendError::Unsupported("sign"))
        }

        async fn verify(
            &self,
            key_id: &str,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, BackendError> {
            let _ = (key_id, message, signature);
            Err(BackendError::Unsupported("verify"))
        }

        async fn issue_x509_svid(
            &self,
            key_id: &str,
            spiffe_id: &str,
            ttl_seconds: u64,
        ) -> Result<X509Svid, BackendError> {
            assert_eq!(key_id, "pki/issue/workload");
            assert_eq!(ttl_seconds, crate::state::DEFAULT_SVID_TTL_SECS);
            self.issued_ids
                .lock()
                .expect("issued ids lock")
                .push(spiffe_id.to_string());
            Ok(X509Svid {
                cert_chain_der: vec![b"leaf".to_vec(), b"issuer".to_vec()],
                leaf_private_key_der: zeroize::Zeroizing::new(b"private-key".to_vec()),
                bundle_der: vec![b"bundle".to_vec()],
            })
        }

        async fn x509_bundle(&self, key_id: &str) -> Result<X509Bundle, BackendError> {
            assert_eq!(key_id, "pki/issue/workload");
            Ok(X509Bundle {
                bundle_der: vec![b"root".to_vec(), b"intermediate".to_vec()],
                crl_der: Vec::new(),
            })
        }
    }

    fn service_with_catalog(catalog_json: &str) -> EnvoySdsGrpc {
        let (catalog, policy, config, warnings) =
            load(catalog_json, POLICY).expect("fixture loads");
        assert!(warnings.is_empty());
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("bao".to_string(), Box::<SdsBackend>::default());
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
        let state = Arc::new(BrokerState::new(catalog, policy, config, manager, "dummy"));
        EnvoySdsGrpc::new(state)
    }

    fn service() -> EnvoySdsGrpc {
        service_with_catalog(CATALOG)
    }

    fn request(uid: u32, resource_names: Vec<&str>) -> Request<DiscoveryRequest> {
        let mut request = Request::new(DiscoveryRequest {
            version_info: String::new(),
            node: None,
            resource_names: resource_names.into_iter().map(str::to_string).collect(),
            type_url: SECRET_TYPE_URL.to_string(),
            response_nonce: String::new(),
            error_detail: None,
        });
        request.extensions_mut().insert(PeerInfo {
            uid: Some(uid),
            ..PeerInfo::default()
        });
        request
    }

    fn decode_secret(any: &Any) -> Secret {
        assert_eq!(any.type_url, SECRET_TYPE_URL);
        Secret::decode(any.value.as_slice()).expect("secret decodes")
    }

    #[tokio::test]
    async fn fetch_secrets_returns_leaf_key_and_bundle_resources() {
        let service = service();
        let response = service
            .fetch_secrets(request(42, vec!["default", "ROOTCA"]))
            .await
            .expect("fetch succeeds")
            .into_inner();
        assert_eq!(response.type_url, SECRET_TYPE_URL);
        assert_eq!(response.resources.len(), 2);

        let cert = decode_secret(&response.resources[0]);
        assert_eq!(cert.name, "default");
        let Some(Type::TlsCertificate(cert)) = cert.r#type else {
            panic!("expected tls certificate");
        };
        // `TlsCertificate` zeroizes on drop, so fields cannot be moved out:
        // assert on borrowed views.
        assert_eq!(
            cert.certificate_chain
                .as_ref()
                .expect("certificate chain")
                .specifier
                .as_ref()
                .expect("inline chain"),
            &Specifier::InlineBytes(b"leafissuer".to_vec())
        );
        assert_eq!(
            cert.private_key
                .as_ref()
                .expect("private key")
                .specifier
                .as_ref()
                .expect("inline key"),
            &Specifier::InlineBytes(b"private-key".to_vec())
        );

        let bundle = decode_secret(&response.resources[1]);
        assert_eq!(bundle.name, "ROOTCA");
        let Some(Type::ValidationContext(context)) = bundle.r#type else {
            panic!("expected validation context");
        };
        assert_eq!(
            context
                .trusted_ca
                .expect("trusted ca")
                .specifier
                .expect("inline ca"),
            Specifier::InlineBytes(b"rootintermediate".to_vec())
        );
    }

    #[tokio::test]
    async fn fetch_secrets_denies_unauthorized_certificate_resource() {
        let service = service();
        let status = service
            .fetch_secrets(request(7, vec!["default"]))
            .await
            .expect_err("denied");
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn fetch_secrets_authenticates_before_reporting_no_sds_issuers() {
        let catalog = r#"{
          "schema": "catalog",
          "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
          "keys": {}
        }"#;
        let service = service_with_catalog(catalog);
        let status = service
            .fetch_secrets(Request::new(DiscoveryRequest {
                version_info: String::new(),
                node: None,
                resource_names: vec!["default".to_string()],
                type_url: SECRET_TYPE_URL.to_string(),
                response_nonce: String::new(),
                error_detail: None,
            }))
            .await
            .expect_err("missing peer credentials fail before issuer inventory");
        assert_eq!(status.code(), Code::Unauthenticated);
    }
}
