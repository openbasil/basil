// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! SPIFFE Workload API service shell.
//!
//! Each method first enforces SPIFFE's `workload.spiffe.io=true` metadata
//! marker before serving SVID and trust-bundle material.

#![allow(clippy::result_large_err)]

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use basil_proto::spiffe::spiffe_workload_api_server::SpiffeWorkloadApi;
use basil_proto::spiffe::{
    JwtBundlesRequest, JwtBundlesResponse, Jwtsvid, JwtsvidRequest, JwtsvidResponse,
    ValidateJwtsvidRequest, ValidateJwtsvidResponse, X509BundlesRequest, X509BundlesResponse,
    X509svid, X509svidRequest, X509svidResponse,
};
use futures::Stream;
use std::collections::HashMap;
use tonic::{Code, Request, Response, Status};

use crate::catalog::policy::Op;
use crate::catalog::{Class, Decision, DenyReason, KeyAlgorithm, KeyEntry};
use crate::decision::DecisionRecord;
use crate::event::BrokerEventKind;
use crate::state::{BrokerState, Generation};
use crate::transport::peer_from_request;

type WorkloadResult<T> = Result<Response<T>, Status>;
type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

/// SPIFFE Workload API adapter.
#[derive(Debug, Clone)]
pub struct SpiffeWorkloadGrpc {
    state: Arc<BrokerState>,
}

impl SpiffeWorkloadGrpc {
    /// Build a Workload API service adapter.
    #[must_use]
    pub const fn new(state: Arc<BrokerState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl SpiffeWorkloadApi for SpiffeWorkloadGrpc {
    type FetchX509SVIDStream = BoxStream<X509svidResponse>;
    type FetchX509BundlesStream = BoxStream<X509BundlesResponse>;
    type FetchJWTBundlesStream = BoxStream<JwtBundlesResponse>;

    async fn fetch_x509svid(
        &self,
        request: Request<X509svidRequest>,
    ) -> WorkloadResult<Self::FetchX509SVIDStream> {
        require_workload_header(&request)?;
        let peer = peer_from_request(&request);
        let uid = peer.uid.ok_or_else(|| {
            Status::new(
                Code::Unauthenticated,
                "missing peer credentials for FetchX509SVID",
            )
        })?;
        let plan = self.x509_issue_plan(uid)?;
        let state = Arc::clone(&self.state);
        let rx = state.events().subscribe();
        let stream = futures::stream::unfold(
            (state, rx, plan, uid, false),
            |(state, mut rx, plan, uid, emitted)| async move {
                if !emitted {
                    let response = issue_x509_response(&state, uid, &plan).await;
                    return Some((response, (state, rx, plan, uid, true)));
                }

                let refresh =
                    tokio::time::sleep(Duration::from_secs(x509_refresh_after_secs(&plan)));
                tokio::pin!(refresh);
                loop {
                    tokio::select! {
                        () = &mut refresh => break,
                        event = rx.recv() => match event {
                            Ok(event) if x509_refresh_event(&plan, &event.kind) => break,
                            Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                        }
                    }
                }

                let response = issue_x509_response(&state, uid, &plan).await;
                Some((response, (state, rx, plan, uid, true)))
            },
        );
        Ok(Response::new(Box::pin(stream)))
    }

    async fn fetch_x509_bundles(
        &self,
        request: Request<X509BundlesRequest>,
    ) -> WorkloadResult<Self::FetchX509BundlesStream> {
        require_workload_header(&request)?;
        let plan = self.x509_bundle_plan()?;
        let state = Arc::clone(&self.state);
        let rx = state.events().subscribe();
        let stream = futures::stream::unfold(
            (state, rx, plan, false),
            |(state, mut rx, plan, emitted)| async move {
                if !emitted {
                    let response = x509_bundles_response(&state, &plan).await;
                    return Some((response, (state, rx, plan, true)));
                }

                loop {
                    match rx.recv().await {
                        Ok(event) if x509_bundle_refresh_event(&plan, &event.kind) => break,
                        Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                    }
                }

                let response = x509_bundles_response(&state, &plan).await;
                Some((response, (state, rx, plan, true)))
            },
        );
        Ok(Response::new(Box::pin(stream)))
    }

    async fn fetch_jwtsvid(
        &self,
        request: Request<JwtsvidRequest>,
    ) -> WorkloadResult<JwtsvidResponse> {
        require_workload_header(&request)?;
        let peer = peer_from_request(&request);
        let uid = peer.uid.ok_or_else(|| {
            Status::new(
                Code::Unauthenticated,
                "missing peer credentials for FetchJWTSVID",
            )
        })?;
        let body = request.get_ref();
        if body.audience.is_empty() || body.audience.iter().any(|aud| aud.trim().is_empty()) {
            return Err(invalid_argument(
                "FetchJWTSVID requires a non-empty audience",
            ));
        }
        if !body.spiffe_id.is_empty() && !is_spiffe_id(body.spiffe_id.as_str()) {
            return Err(invalid_argument("requested SPIFFE ID is malformed"));
        }

        // Pin ONE generation for the whole RPC (basil-gymz): the issuer choice +
        // mint authorization AND the templated SPIFFE id are rendered against the
        // same catalog/config snapshot. A concurrent reload between the two loads
        // could otherwise template the id against a different generation than the
        // one that authorized the mint. One pin keeps them coherent by construction.
        let generation = Arc::clone(&self.state.load_generation());
        let issuer = self.jwt_issuer(&generation, uid, body.spiffe_id.as_str())?;
        let spiffe_id = requested_or_templated_spiffe_id(
            &generation,
            uid,
            body.spiffe_id.as_str(),
            issuer.entry,
        )?;
        let issuer_id = issuer
            .entry
            .labels
            .get("spiffe_id")
            .unwrap_or(issuer.name.as_str());
        let alg = svid_alg(issuer.entry.key_type)?;

        let mut svids = Vec::with_capacity(body.audience.len());
        for audience in &body.audience {
            let token = crate::minter::mint_svid(
                issuer.backend,
                &issuer.path,
                issuer_id,
                alg,
                &spiffe_id,
                audience,
                Some(DEFAULT_JWT_SVID_TTL_SECS),
                &serde_json::Value::Null,
            )
            .await
            .map_err(|e| mint_status(&e))?;
            svids.push(Jwtsvid {
                spiffe_id: spiffe_id.clone(),
                svid: token,
                hint: String::new(),
            });
        }
        Ok(Response::new(JwtsvidResponse { svids }))
    }

    async fn fetch_jwt_bundles(
        &self,
        request: Request<JwtBundlesRequest>,
    ) -> WorkloadResult<Self::FetchJWTBundlesStream> {
        require_workload_header(&request)?;
        let plan = self.jwt_bundle_plan()?;
        let state = Arc::clone(&self.state);
        let rx = state.events().subscribe();
        let stream = futures::stream::unfold(
            (state, rx, plan, false),
            |(state, mut rx, plan, emitted)| async move {
                if !emitted {
                    let response = jwt_bundles_response(&state, &plan).await;
                    return Some((response, (state, rx, plan, true)));
                }

                loop {
                    match rx.recv().await {
                        Ok(event) if jwt_bundle_refresh_event(&plan, &event.kind) => break,
                        Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                    }
                }

                let response = jwt_bundles_response(&state, &plan).await;
                Some((response, (state, rx, plan, true)))
            },
        );
        Ok(Response::new(Box::pin(stream)))
    }

    async fn validate_jwtsvid(
        &self,
        request: Request<ValidateJwtsvidRequest>,
    ) -> WorkloadResult<ValidateJwtsvidResponse> {
        require_workload_header(&request)?;
        let peer = peer_from_request(&request);
        let uid = peer.uid.ok_or_else(|| {
            Status::new(
                Code::Unauthenticated,
                "missing peer credentials for ValidateJWTSVID",
            )
        })?;
        let body = request.get_ref();
        if body.audience.trim().is_empty() || body.svid.trim().is_empty() {
            return Err(invalid_argument(
                "ValidateJWTSVID requires a non-empty audience and SVID",
            ));
        }

        let generation = Arc::clone(&self.state.load_generation());
        let unverified = unverified_jwt_svid_claims(&body.svid)?;
        let issuer = self.jwt_validation_issuer(&generation, uid, &unverified)?;
        let validation = validate_jwt_svid(
            issuer.backend,
            &issuer.path,
            issuer.entry,
            &issuer.issuer_id,
            &body.audience,
            &body.svid,
        )
        .await?;
        let trust_domain = issuer
            .entry
            .labels
            .get("trust_domain")
            .ok_or_else(validation_failed)?;
        reject_revoked_jwtsvid(
            self.state.jwt_revocations(),
            trust_domain,
            &validation.claims,
        )?;
        Ok(Response::new(ValidateJwtsvidResponse {
            spiffe_id: validation.spiffe_id,
            claims: Some(json_struct(validation.claims)),
        }))
    }
}

fn require_workload_header<T>(request: &Request<T>) -> Result<(), Status> {
    let mut values = request.metadata().get_all("workload.spiffe.io").iter();
    let valid = values
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "true")
        && values.next().is_none();
    if valid {
        return Ok(());
    }

    Err(Status::new(
        Code::InvalidArgument,
        "SPIFFE Workload API requests require workload.spiffe.io=true",
    ))
}

const DEFAULT_JWT_SVID_TTL_SECS: u64 = 300;

struct JwtIssuer<'a> {
    name: String,
    path: String,
    entry: &'a KeyEntry,
    backend: &'a dyn crate::backend::Backend,
}

struct JwtValidationIssuer<'a> {
    path: String,
    issuer_id: String,
    entry: &'a KeyEntry,
    backend: &'a dyn crate::backend::Backend,
}

struct ValidJwtSvid {
    spiffe_id: String,
    claims: serde_json::Value,
}

#[derive(Debug, Clone)]
struct X509IssuePlan {
    key_name: String,
    spiffe_id: String,
    trust_domain: String,
    ttl_seconds: u64,
}

#[derive(Debug, Clone)]
struct X509BundlePlan {
    key_name: String,
    trust_domain: String,
}

#[derive(Debug, Clone)]
struct JwtBundlePlan {
    key_name: String,
    trust_domain: String,
}

impl SpiffeWorkloadGrpc {
    fn x509_issue_plan(&self, uid: u32) -> Result<X509IssuePlan, Status> {
        // Pin one generation for the whole plan: every PDP decision and the
        // templated SPIFFE-ID rendering draw from the same coherent snapshot.
        let generation = self.state.load_generation();
        let actor = generation.pdp().resolve_unix_actor(uid).map_err(|_| {
            Status::new(
                Code::PermissionDenied,
                "no configured subject for FetchX509SVID caller",
            )
        })?;
        let mut saw_candidate = false;
        for (name, entry) in &generation.catalog().keys {
            if !is_x509_svid_issuer(entry) {
                continue;
            }
            saw_candidate = true;
            let decision = generation.pdp().decide(&actor, Op::Mint, name);
            self.state
                .record_decision(&DecisionRecord::from_actor_decision(
                    generation.id(),
                    &actor,
                    Op::Mint,
                    name,
                    &decision,
                ));
            if decision.is_deny() {
                continue;
            }
            let spiffe_id = requested_or_templated_spiffe_id(&generation, uid, "", entry)?;
            let trust_domain = entry
                .labels
                .get("trust_domain")
                .ok_or_else(|| {
                    Status::new(
                        Code::Internal,
                        "X.509-SVID issuer has no trust_domain label",
                    )
                })?
                .to_string();
            return Ok(X509IssuePlan {
                key_name: name.clone(),
                spiffe_id,
                trust_domain,
                ttl_seconds: self.state.limits().svid_ttl_secs.max(1),
            });
        }

        let reason = if saw_candidate {
            "not authorized to mint an X.509-SVID"
        } else {
            "no X.509-SVID issuer is configured"
        };
        self.state
            .record_decision(&DecisionRecord::from_actor_decision(
                generation.id(),
                &actor,
                Op::Mint,
                "spiffe.x509_svid",
                &Decision::Deny {
                    reason: DenyReason::NotPermitted,
                },
            ));
        Err(Status::new(Code::PermissionDenied, reason))
    }

    /// Find the JWT-SVID issuer for `requested_spiffe_id` and authorize the mint,
    /// deciding against the **caller-pinned** `generation` so the whole
    /// `fetch_jwtsvid` RPC stays coherent across a concurrent reload (basil-gymz).
    fn jwt_issuer<'a>(
        &'a self,
        generation: &'a Generation,
        uid: u32,
        requested_spiffe_id: &str,
    ) -> Result<JwtIssuer<'a>, Status> {
        let actor = generation.pdp().resolve_unix_actor(uid).map_err(|_| {
            Status::new(
                Code::PermissionDenied,
                "no configured subject for FetchJWTSVID caller",
            )
        })?;
        let mut saw_candidate = false;
        for (name, entry) in &generation.catalog().keys {
            if !is_jwt_svid_issuer(entry) {
                continue;
            }
            if !requested_spiffe_id.is_empty()
                && !spiffe_id_matches_trust_domain(requested_spiffe_id, entry)
            {
                continue;
            }
            saw_candidate = true;
            let decision = generation.pdp().decide(&actor, Op::Mint, name);
            self.state
                .record_decision(&DecisionRecord::from_actor_decision(
                    generation.id(),
                    &actor,
                    Op::Mint,
                    name,
                    &decision,
                ));
            if decision.is_deny() {
                continue;
            }
            let routed = self
                .state
                .manager()
                .resolve(name)
                .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
            return Ok(JwtIssuer {
                name: name.clone(),
                path: routed.path().to_string(),
                entry,
                backend: routed.backend,
            });
        }

        let reason = if saw_candidate {
            "not authorized to mint a JWT-SVID"
        } else {
            "no JWT-SVID issuer matches the requested SPIFFE ID"
        };
        self.state
            .record_decision(&DecisionRecord::from_actor_decision(
                generation.id(),
                &actor,
                Op::Mint,
                "spiffe.jwt_svid",
                &Decision::Deny {
                    reason: DenyReason::NotPermitted,
                },
            ));
        Err(Status::new(Code::PermissionDenied, reason))
    }

    fn jwt_validation_issuer<'a>(
        &'a self,
        generation: &'a Generation,
        uid: u32,
        claims: &serde_json::Value,
    ) -> Result<JwtValidationIssuer<'a>, Status> {
        let actor = generation.pdp().resolve_unix_actor(uid).map_err(|_| {
            Status::new(
                Code::PermissionDenied,
                "no configured subject for ValidateJWTSVID caller",
            )
        })?;
        let iss = claims
            .get("iss")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(validation_failed)?;
        let sub = claims
            .get("sub")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(validation_failed)?;
        if !is_spiffe_id(sub) {
            return Err(validation_failed());
        }

        let mut saw_candidate = false;
        for (name, entry) in &generation.catalog().keys {
            if !is_jwt_svid_issuer(entry) || !spiffe_id_matches_trust_domain(sub, entry) {
                continue;
            }
            let issuer_id = entry
                .labels
                .get("spiffe_id")
                .map_or_else(|| name.as_str(), |value| value);
            /* ubs constant time equality check is not needed for the iss field */
            /* ubs:ignore */
            if issuer_id != iss {
                continue;
            }
            saw_candidate = true;
            let decision = generation.pdp().decide(&actor, Op::Validate, name);
            self.state
                .record_decision(&DecisionRecord::from_actor_decision(
                    generation.id(),
                    &actor,
                    Op::Validate,
                    name,
                    &decision,
                ));
            if decision.is_deny() {
                continue;
            }
            let routed = self
                .state
                .manager()
                .resolve(name)
                .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
            return Ok(JwtValidationIssuer {
                path: routed.path().to_string(),
                issuer_id: issuer_id.to_string(),
                entry,
                backend: routed.backend,
            });
        }

        if saw_candidate {
            return Err(Status::new(
                Code::PermissionDenied,
                "not authorized to validate a JWT-SVID",
            ));
        }
        Err(validation_failed())
    }

    fn x509_bundle_plan(&self) -> Result<Vec<X509BundlePlan>, Status> {
        let generation = self.state.load_generation();
        let plans: Vec<_> = generation
            .catalog()
            .keys
            .iter()
            .filter(|(_, entry)| is_x509_svid_issuer(entry))
            .filter_map(|(name, entry)| {
                entry
                    .labels
                    .get("trust_domain")
                    .map(|trust_domain| X509BundlePlan {
                        key_name: name.clone(),
                        trust_domain: trust_domain.to_string(),
                    })
            })
            .collect();
        if plans.is_empty() {
            Err(Status::new(
                Code::FailedPrecondition,
                "no X.509 bundle publisher is configured",
            ))
        } else {
            Ok(plans)
        }
    }

    fn jwt_bundle_plan(&self) -> Result<Vec<JwtBundlePlan>, Status> {
        let generation = self.state.load_generation();
        let plans: Vec<_> = generation
            .catalog()
            .keys
            .iter()
            .filter(|(_, entry)| is_jwt_svid_issuer(entry))
            .filter_map(|(name, entry)| {
                entry
                    .labels
                    .get("trust_domain")
                    .map(|trust_domain| JwtBundlePlan {
                        key_name: name.clone(),
                        trust_domain: trust_domain.to_string(),
                    })
            })
            .collect();
        if plans.is_empty() {
            Err(Status::new(
                Code::FailedPrecondition,
                "no JWT bundle publisher is configured",
            ))
        } else {
            Ok(plans)
        }
    }
}

async fn issue_x509_response(
    state: &BrokerState,
    _uid: u32,
    plan: &X509IssuePlan,
) -> Result<X509svidResponse, Status> {
    let mut issued = state
        .manager()
        .issue_x509_svid(&plan.key_name, &plan.spiffe_id, plan.ttl_seconds)
        .await
        .map_err(|err| x509_issue_status(&err))?;
    Ok(X509svidResponse {
        svids: vec![X509svid {
            spiffe_id: plan.spiffe_id.clone(),
            x509_svid: issued.cert_chain_der.concat(),
            // Move (never copy) the leaf key out of its `Zeroizing` buffer:
            // the proto field is then the only plain copy, and `X509svid`
            // zeroizes it on drop after tonic encodes the response.
            x509_svid_key: std::mem::take(&mut *issued.leaf_private_key_der),
            bundle: issued.bundle_der.concat(),
            hint: String::new(),
        }],
        crl: Vec::new(),
        federated_bundles: std::collections::HashMap::default(),
    })
}

fn x509_refresh_after_secs(plan: &X509IssuePlan) -> u64 {
    (plan.ttl_seconds / 2).max(1)
}

fn x509_refresh_event(plan: &X509IssuePlan, kind: &BrokerEventKind) -> bool {
    match kind {
        /* ubs: constant time equality check is not needed for checking key name */
        BrokerEventKind::KeyRotated { key_id, .. } => {
            /* ubs:ignore */
            key_id == &plan.key_name
        }
        BrokerEventKind::BundleChanged { trust_domain }
        | BrokerEventKind::Revoked { trust_domain, .. } => {
            /* ubs:ignore */
            trust_domain == &plan.trust_domain
        }
    }
}

fn x509_bundle_refresh_event(plans: &[X509BundlePlan], kind: &BrokerEventKind) -> bool {
    plans.iter().any(|plan| match kind {
        BrokerEventKind::KeyRotated { key_id, .. } => {
            /* ubs:ignore */
            key_id == &plan.key_name
        }
        BrokerEventKind::BundleChanged { trust_domain }
        | BrokerEventKind::Revoked { trust_domain, .. } => {
            /* ubs:ignore */
            trust_domain == &plan.trust_domain
        }
    })
}

fn jwt_bundle_refresh_event(plans: &[JwtBundlePlan], kind: &BrokerEventKind) -> bool {
    plans.iter().any(|plan| match kind {
        BrokerEventKind::KeyRotated { key_id, .. } => {
            /* ubs:ignore */
            key_id == &plan.key_name
        }
        BrokerEventKind::BundleChanged { trust_domain }
        | BrokerEventKind::Revoked { trust_domain, .. } => {
            /* ubs:ignore */
            trust_domain == &plan.trust_domain
        }
    })
}

async fn x509_bundles_response(
    state: &BrokerState,
    plans: &[X509BundlePlan],
) -> Result<X509BundlesResponse, Status> {
    let mut bundles = HashMap::new();
    let mut crl = Vec::new();
    for plan in plans {
        let routed = state
            .manager()
            .resolve(&plan.key_name)
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let bundle = routed
            .backend
            .x509_bundle(routed.path())
            .await
            .map_err(|_| upstream_unavailable())?;
        bundles.insert(
            format!("spiffe://{}", plan.trust_domain),
            bundle.bundle_der.concat(),
        );
        if !bundle.crl_der.is_empty() {
            crl.push(bundle.crl_der);
        }
    }
    Ok(X509BundlesResponse { crl, bundles })
}

async fn jwt_bundles_response(
    state: &BrokerState,
    plans: &[JwtBundlePlan],
) -> Result<JwtBundlesResponse, Status> {
    let mut bundles = HashMap::new();
    for plan in plans {
        let routed = state
            .manager()
            .resolve(&plan.key_name)
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let alg = svid_alg(routed.entry.key_type)?;
        // Reflect the rotation grace window: publish every issuer version still
        // inside `[grace_floor ..= latest]` so a verifier can validate a token
        // signed by a recently rotated-away version. Same generator the HTTP JWKS
        // uses (`basil-uce.2`), so the two surfaces never diverge.
        let limits = state.limits();
        let jwks =
            crate::minter::jwt_svid_jwks_grace(routed.backend, routed.path(), alg, |latest| {
                limits.grace_floor(latest)
            })
            .await
            .map_err(|_| upstream_unavailable())?;
        bundles.insert(format!("spiffe://{}", plan.trust_domain), jwks);
    }
    Ok(JwtBundlesResponse { bundles })
}

async fn validate_jwt_svid(
    backend: &dyn crate::backend::Backend,
    key_path: &str,
    entry: &KeyEntry,
    issuer_id: &str,
    audience: &str,
    token: &str,
) -> Result<ValidJwtSvid, Status> {
    let alg = svid_alg(entry.key_type)?;
    let public_key = backend
        .public_key(key_path)
        .await
        .map_err(|_| validation_failed())?;
    let decoding_key = decoding_key(&public_key, alg)?;
    let algorithm = jwt_algorithm(alg);
    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
    validation.set_issuer(&[issuer_id]);
    validation.set_audience(&[audience]);
    let token_data = jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
        .map_err(|_| validation_failed())?;
    let spiffe_id = token_data
        .claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .filter(|sub| is_spiffe_id(sub) && spiffe_id_matches_trust_domain(sub, entry))
        .ok_or_else(validation_failed)?
        .to_string();
    Ok(ValidJwtSvid {
        spiffe_id,
        claims: token_data.claims,
    })
}

fn unverified_jwt_svid_claims(token: &str) -> Result<serde_json::Value, Status> {
    let mut parts = token.split('.');
    let _header = parts.next().ok_or_else(validation_failed)?;
    let claims = parts.next().ok_or_else(validation_failed)?;
    let _signature = parts.next().ok_or_else(validation_failed)?;
    if parts.next().is_some() {
        return Err(validation_failed());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(claims)
        .map_err(|_| validation_failed())?;
    serde_json::from_slice(&bytes).map_err(|_| validation_failed())
}

fn reject_revoked_jwtsvid(
    store: &crate::revocation::JwtRevocationStore,
    trust_domain: &str,
    claims: &serde_json::Value,
) -> Result<(), Status> {
    let Some(jti) = claims.get("jti").and_then(serde_json::Value::as_str) else {
        return Ok(());
    };
    if store.is_revoked(trust_domain, jti) {
        return Err(validation_failed());
    }
    Ok(())
}

fn decoding_key(
    public_key: &[u8],
    alg: crate::minter::SvidAlg,
) -> Result<jsonwebtoken::DecodingKey, Status> {
    match alg {
        crate::minter::SvidAlg::EdDsa if public_key.len() == 32 => {
            Ok(jsonwebtoken::DecodingKey::from_ed_der(public_key))
        }
        crate::minter::SvidAlg::EdDsa => Err(validation_failed()),
        crate::minter::SvidAlg::Rs256 => {
            if let Ok(pem) = std::str::from_utf8(public_key)
                && pem.trim_start().starts_with("-----BEGIN ")
            {
                return jsonwebtoken::DecodingKey::from_rsa_pem(public_key)
                    .map_err(|_| validation_failed());
            }
            Ok(jsonwebtoken::DecodingKey::from_rsa_der(public_key))
        }
        crate::minter::SvidAlg::Es256 => {
            if let Ok(pem) = std::str::from_utf8(public_key)
                && pem.trim_start().starts_with("-----BEGIN ")
            {
                return jsonwebtoken::DecodingKey::from_ec_pem(public_key)
                    .map_err(|_| validation_failed());
            }
            Ok(jsonwebtoken::DecodingKey::from_ec_der(public_key))
        }
        crate::minter::SvidAlg::Es384 => {
            if let Ok(pem) = std::str::from_utf8(public_key)
                && pem.trim_start().starts_with("-----BEGIN ")
            {
                return jsonwebtoken::DecodingKey::from_ec_pem(public_key)
                    .map_err(|_| validation_failed());
            }
            Ok(jsonwebtoken::DecodingKey::from_ec_der(public_key))
        }
    }
}

const fn jwt_algorithm(alg: crate::minter::SvidAlg) -> jsonwebtoken::Algorithm {
    match alg {
        crate::minter::SvidAlg::EdDsa => jsonwebtoken::Algorithm::EdDSA,
        crate::minter::SvidAlg::Rs256 => jsonwebtoken::Algorithm::RS256,
        crate::minter::SvidAlg::Es256 => jsonwebtoken::Algorithm::ES256,
        crate::minter::SvidAlg::Es384 => jsonwebtoken::Algorithm::ES384,
    }
}

fn is_x509_svid_issuer(entry: &KeyEntry) -> bool {
    entry.class == Class::Asymmetric
        && entry.labels.get("svid_kind") == Some("x509")
        && entry.labels.get("trust_domain").is_some()
}

fn is_jwt_svid_issuer(entry: &KeyEntry) -> bool {
    /* ubs false positive: do not need constant time equality checks here */
    entry.class == Class::Asymmetric
        /* ubs:ignore */
        && entry.labels.get("svid_kind") == Some("jwt")
        && entry.labels.get("trust_domain").is_some()
        // Only a SPIFFE JWT-SVID profile algorithm (rsa-*/ec-* → RS*/ES*/PS*)
        // is a valid issuer: an EdDSA/ed25519 token is rejected by conforming
        // SPIFFE clients. The catalog loader fails closed on such a misconfig at
        // boot/check (`validate_jwt_svid_issuer_alg`); this keeps the runtime
        // predicate consistent (defense in depth) so a bypassed load can never
        // select a non-profile issuer.
        && entry
            .key_type
            .is_some_and(KeyAlgorithm::is_spiffe_jwt_svid_profile)
}

fn requested_or_templated_spiffe_id(
    generation: &Generation,
    uid: u32,
    requested: &str,
    entry: &KeyEntry,
) -> Result<String, Status> {
    let trust_domain = entry
        .labels
        .get("trust_domain")
        .ok_or_else(|| Status::new(Code::Internal, "JWT-SVID issuer has no trust_domain label"))?;
    let segment = generation
        .config()
        .names
        .users
        .get(&uid)
        .map_or_else(|| uid.to_string(), std::string::ToString::to_string);
    let id = format!("spiffe://{trust_domain}/{segment}");
    if !is_spiffe_id(&id) {
        return Err(Status::new(
            Code::Internal,
            "templated SPIFFE ID is malformed",
        ));
    }

    if requested.is_empty() || requested == id {
        Ok(id)
    } else if is_spiffe_id(requested) && spiffe_id_matches_trust_domain(requested, entry) {
        Err(Status::new(
            Code::PermissionDenied,
            "requested SPIFFE ID is outside the caller identity",
        ))
    } else {
        Err(invalid_argument(
            "requested SPIFFE ID is malformed or out of trust domain",
        ))
    }
}

fn spiffe_id_matches_trust_domain(spiffe_id: &str, entry: &KeyEntry) -> bool {
    entry
        .labels
        .get("trust_domain")
        .is_some_and(|trust_domain| {
            spiffe_id
                .strip_prefix("spiffe://")
                .and_then(|rest| rest.split_once('/'))
                /* ubs constant time equality check is not needed here */
                /* ubs:ignore */
                .is_some_and(|(td, path)| td == trust_domain && !path.is_empty())
        })
}

/// Pick the JWS `alg` for a JWT-SVID issuer from its key type.
///
/// A JWT-SVID issuer must use a SPIFFE JWT-SVID profile signing algorithm
/// (`RS256` for `rsa-*`; `ES256` for P-256). The catalog loader
/// fails closed on any non-profile `svid_kind=jwt` issuer at boot/check
/// ([`validate_jwt_svid_issuer_alg`](crate::catalog::loader)) and the runtime
/// predicate [`is_jwt_svid_issuer`] re-checks [`KeyAlgorithm::is_spiffe_jwt_svid_profile`],
/// so an `EdDSA`/Ed25519 issuer can never reach this function. The non-profile
/// arms therefore fail closed with `FailedPrecondition` (never a panic) as a
/// defense-in-depth backstop rather than asserting unreachability.
fn svid_alg(key_type: Option<KeyAlgorithm>) -> Result<crate::minter::SvidAlg, Status> {
    match key_type {
        Some(KeyAlgorithm::Rsa2048) => Ok(crate::minter::SvidAlg::Rs256),
        Some(KeyAlgorithm::EcdsaP256) => Ok(crate::minter::SvidAlg::Es256),
        Some(KeyAlgorithm::EcdsaP384) => Ok(crate::minter::SvidAlg::Es384),
        // Ed25519/Ed25519Nkey (`EdDSA`) is not a SPIFFE JWT-SVID profile alg and
        // is rejected at load by the fail-closed guardrail; this arm is the
        // runtime backstop for a bypassed load. AEAD/KEM key types likewise
        // cannot sign JWT-SVIDs.
        _ => Err(Status::new(
            Code::FailedPrecondition,
            "JWT-SVID issuer key cannot sign JWT-SVIDs",
        )),
    }
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

fn invalid_argument(message: &'static str) -> Status {
    Status::new(Code::InvalidArgument, message)
}

fn validation_failed() -> Status {
    invalid_argument("JWT-SVID validation failed")
}

fn upstream_unavailable() -> Status {
    Status::new(Code::Unavailable, "backend unavailable")
}

fn json_struct(value: serde_json::Value) -> prost_types::Struct {
    let serde_json::Value::Object(fields) = value else {
        return prost_types::Struct::default();
    };
    prost_types::Struct {
        fields: fields
            .into_iter()
            .map(|(key, value)| (key, json_value(value)))
            .collect(),
    }
}

fn json_value(value: serde_json::Value) -> prost_types::Value {
    let kind = match value {
        serde_json::Value::Null => prost_types::value::Kind::NullValue(0),
        serde_json::Value::Bool(value) => prost_types::value::Kind::BoolValue(value),
        serde_json::Value::Number(value) => {
            prost_types::value::Kind::NumberValue(value.as_f64().unwrap_or(0.0))
        }
        serde_json::Value::String(value) => prost_types::value::Kind::StringValue(value),
        serde_json::Value::Array(values) => {
            prost_types::value::Kind::ListValue(prost_types::ListValue {
                values: values.into_iter().map(json_value).collect(),
            })
        }
        serde_json::Value::Object(_) => prost_types::value::Kind::StructValue(json_struct(value)),
    };
    prost_types::Value { kind: Some(kind) }
}

fn mint_status(err: &crate::minter::GenericMintError) -> Status {
    match err {
        crate::minter::GenericMintError::Reserved(e) => {
            Status::new(Code::InvalidArgument, e.to_string())
        }
        crate::minter::GenericMintError::Backend(_) => upstream_unavailable(),
    }
}

fn x509_issue_status(err: &crate::manager::ManagerError) -> Status {
    match err {
        crate::manager::ManagerError::UnknownKey(_) => {
            Status::new(Code::PermissionDenied, "not authorized")
        }
        crate::manager::ManagerError::Unsupported(_)
        | crate::manager::ManagerError::OpNotValidForClass { .. }
        | crate::manager::ManagerError::UnsupportedKeyType { .. } => {
            Status::new(Code::FailedPrecondition, err.to_string())
        }
        crate::manager::ManagerError::Backend(_) => upstream_unavailable(),
        crate::manager::ManagerError::UnknownBackend { .. }
        | crate::manager::ManagerError::AlgorithmMismatch { .. }
        | crate::manager::ManagerError::KemAlgorithmMismatch { .. }
        | crate::manager::ManagerError::ValueRotateNeedsSet(_)
        // Neither a sealing nor a materialize-to-sign error (nor a missing
        // public_path, nor a provider-dispatch ML-DSA error) can arise on the
        // X.509 issuance path (a PKI issuer is asymmetric+pki, not sealing, kv2,
        // or ML-DSA software custody); treat it as an internal invariant breach.
        | crate::manager::ManagerError::Sealing(_)
        | crate::manager::ManagerError::Signing(_)
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

    use async_trait::async_trait;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use crate::backend::{Backend, BackendError, NewKey, X509Bundle, X509Svid};
    use crate::catalog::loader::load;
    use crate::manager::BackendManager;
    use crate::peer::PeerInfo;
    use crate::state::{BrokerLimits, DEFAULT_SVID_TTL_SECS};

    const CATALOG: &str = r#"{
      "schemaVersion": 1,
      "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
      "keys": {
        "spire.jwt": {
          "class": "asymmetric", "keyType": "rsa-2048", "backend": "bao",
          "path": "jwt-issuer", "writable": false, "missing": "error",
          "labels": ["svid_kind=jwt", "trust_domain=example.org", "spiffe_id=spiffe://example.org/basil"],
          "description": "JWT-SVID issuer"
        },
        "spire.x509": {
          "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
          "engine": "pki", "path": "pki/issue/workload", "writable": false, "missing": "error",
          "labels": ["svid_kind=x509", "trust_domain=example.org"],
          "description": "X.509-SVID issuer"
        }
      }
    }"#;

    const POLICY: &str = r#"{
      "schemaVersion": 2,
      "subjects": {
        "svc.api": { "allOf": [ { "kind": "unix", "uid": 9100 } ] }
      },
      "roles": { "minter": ["mint"], "validator": ["validate"] },
      "rules": [
        { "id": "allow-svc-jwt", "subjects": ["svc.api"], "action": ["role:minter"], "target": ["spire.jwt"] },
        { "id": "allow-svc-x509", "subjects": ["svc.api"], "action": ["role:minter"], "target": ["spire.x509"] },
        { "id": "allow-svc-validate", "subjects": ["svc.api"], "action": ["role:validator"], "target": ["spire.jwt"] }
      ],
      "config": {
        "names": { "users": { "9100": "svc-api" }, "groups": {} },
        "memberships": {}
      }
    }"#;

    #[derive(Default)]
    struct JwtBackend {
        sign_calls: std::sync::atomic::AtomicUsize,
        x509_calls: std::sync::Mutex<Vec<String>>,
        expected_x509_ttl: std::sync::atomic::AtomicU64,
    }

    #[async_trait]
    impl Backend for JwtBackend {
        fn kind(&self) -> &'static str {
            "jwt-test"
        }

        async fn new_key(&self, key_type: basil_proto::KeyType) -> Result<NewKey, BackendError> {
            let _ = key_type;
            Err(BackendError::Unsupported("new_key"))
        }

        async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
            let _ = key_id;
            Ok(test_public_key())
        }

        async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
            let _ = key_id;
            self.sign_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            test_rs256_sign(message)
        }

        async fn sign_with_options(
            &self,
            key_id: &str,
            message: &[u8],
            options: crate::backend::SignOptions,
        ) -> Result<Vec<u8>, BackendError> {
            let _ = key_id;
            // The fixture issuer is rsa-2048 → the minter requests RS256.
            if options != crate::backend::SignOptions::Rs256Pkcs1v15Sha256 {
                return Err(BackendError::Unsupported("jwt-test sign options"));
            }
            self.sign_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            test_rs256_sign(message)
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
            assert_eq!(
                ttl_seconds,
                self.expected_x509_ttl
                    .load(std::sync::atomic::Ordering::SeqCst)
            );
            self.x509_calls
                .lock()
                .expect("calls lock")
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
                bundle_der: vec![b"bundle".to_vec(), b"issuer".to_vec()],
                crl_der: b"crl".to_vec(),
            })
        }
    }

    fn service() -> (SpiffeWorkloadGrpc, Arc<JwtBackend>) {
        service_with_limits(BrokerLimits::default())
    }

    fn service_with_limits(limits: BrokerLimits) -> (SpiffeWorkloadGrpc, Arc<JwtBackend>) {
        let (catalog, policy, config, warnings) = load(CATALOG, POLICY).expect("fixture loads");
        assert!(warnings.is_empty());
        let backend = Arc::new(JwtBackend::default());
        backend.expected_x509_ttl.store(
            limits.svid_ttl_secs.max(1),
            std::sync::atomic::Ordering::SeqCst,
        );
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("bao".into(), Box::new(TestBackend(backend.clone())));
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
        let state = Arc::new(BrokerState::with_limits(
            catalog, policy, config, manager, "jwt-test", limits,
        ));
        (SpiffeWorkloadGrpc::new(state), backend)
    }

    struct TestBackend(Arc<JwtBackend>);

    #[async_trait]
    impl Backend for TestBackend {
        fn kind(&self) -> &'static str {
            self.0.kind()
        }

        async fn new_key(&self, key_type: basil_proto::KeyType) -> Result<NewKey, BackendError> {
            self.0.new_key(key_type).await
        }

        async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
            self.0.public_key(key_id).await
        }

        async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
            self.0.sign(key_id, message).await
        }

        async fn sign_with_options(
            &self,
            key_id: &str,
            message: &[u8],
            options: crate::backend::SignOptions,
        ) -> Result<Vec<u8>, BackendError> {
            self.0.sign_with_options(key_id, message, options).await
        }

        async fn verify(
            &self,
            key_id: &str,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, BackendError> {
            self.0.verify(key_id, message, signature).await
        }

        async fn issue_x509_svid(
            &self,
            key_id: &str,
            spiffe_id: &str,
            ttl_seconds: u64,
        ) -> Result<X509Svid, BackendError> {
            self.0.issue_x509_svid(key_id, spiffe_id, ttl_seconds).await
        }

        async fn x509_bundle(&self, key_id: &str) -> Result<X509Bundle, BackendError> {
            self.0.x509_bundle(key_id).await
        }
    }

    fn jwt_request(uid: u32, spiffe_id: &str, audience: Vec<&str>) -> Request<JwtsvidRequest> {
        let mut request = Request::new(JwtsvidRequest {
            audience: audience.into_iter().map(str::to_string).collect(),
            spiffe_id: spiffe_id.to_string(),
        });
        request
            .metadata_mut()
            .insert("workload.spiffe.io", "true".parse().expect("metadata"));
        request.extensions_mut().insert(PeerInfo {
            uid: Some(uid),
            ..PeerInfo::default()
        });
        request
    }

    fn x509_request(uid: u32) -> Request<X509svidRequest> {
        let mut request = Request::new(X509svidRequest {});
        request
            .metadata_mut()
            .insert("workload.spiffe.io", "true".parse().expect("metadata"));
        request.extensions_mut().insert(PeerInfo {
            uid: Some(uid),
            ..PeerInfo::default()
        });
        request
    }

    fn x509_bundles_request() -> Request<X509BundlesRequest> {
        let mut request = Request::new(X509BundlesRequest {});
        request
            .metadata_mut()
            .insert("workload.spiffe.io", "true".parse().expect("metadata"));
        request
    }

    fn jwt_bundles_request() -> Request<JwtBundlesRequest> {
        let mut request = Request::new(JwtBundlesRequest {});
        request
            .metadata_mut()
            .insert("workload.spiffe.io", "true".parse().expect("metadata"));
        request
    }

    fn validate_request(uid: u32, audience: &str, svid: String) -> Request<ValidateJwtsvidRequest> {
        let mut request = Request::new(ValidateJwtsvidRequest {
            audience: audience.to_string(),
            svid,
        });
        request
            .metadata_mut()
            .insert("workload.spiffe.io", "true".parse().expect("metadata"));
        request.extensions_mut().insert(PeerInfo {
            uid: Some(uid),
            ..PeerInfo::default()
        });
        request
    }

    fn token_claims(token: &str) -> serde_json::Value {
        let mut parts = token.split('.');
        let _header = parts.next().expect("header");
        let claims = parts.next().expect("claims");
        let bytes = URL_SAFE_NO_PAD.decode(claims).expect("claims b64");
        serde_json::from_slice(&bytes).expect("claims json")
    }

    /// The fixture's JWT-SVID issuer is `rsa-2048` (the SPIFFE JWT-SVID profile;
    /// an `ed25519` issuer is now rejected at catalog load, basil-6o4). One RSA
    /// keypair backs both the mock backend's published public key and the
    /// `valid_jwt_svid` signer so validation round-trips under `RS256`.
    fn test_issuer_key() -> &'static rsa::RsaPrivateKey {
        use std::sync::LazyLock;
        static KEY: LazyLock<rsa::RsaPrivateKey> = LazyLock::new(|| {
            let mut rng = rand::thread_rng();
            rsa::RsaPrivateKey::new(&mut rng, 2048).expect("test rsa keygen")
        });
        &KEY
    }

    /// The issuer's public half as SPKI PEM: what the JWT-SVID JWKS builder and
    /// the validation `decoding_key` (RS256) consume (both accept SPKI PEM).
    fn test_public_key() -> Vec<u8> {
        use rsa::pkcs8::{EncodePublicKey, LineEnding};
        rsa::RsaPublicKey::from(test_issuer_key())
            .to_public_key_pem(LineEnding::LF)
            .expect("spki pem")
            .into_bytes()
    }

    /// A real `RS256` signature over `input` with the fixture issuer key, as the
    /// raw signature bytes the minter re-encodes into the JWS. (`jsonwebtoken`
    /// returns a base64url string; decode it back to bytes.)
    fn test_rs256_sign(input: &[u8]) -> Result<Vec<u8>, BackendError> {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        let private_pem = test_issuer_key()
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pkcs1 pem");
        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("encoding key");
        let b64 = jsonwebtoken::crypto::sign(input, &encoding_key, jsonwebtoken::Algorithm::RS256)
            .map_err(|e| BackendError::Backend(e.to_string()))?;
        URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| BackendError::Backend(e.to_string()))
    }

    fn valid_jwt_svid(audience: &str, expires_at: u64) -> String {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        let claims = serde_json::json!({
            "iss": "spiffe://example.org/basil",
            "sub": "spiffe://example.org/svc-api",
            "aud": audience,
            "iat": expires_at.saturating_sub(60),
            "exp": expires_at,
            "jti": "test-jti",
            "role": "api",
        });
        let private_pem = test_issuer_key()
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pkcs1 pem");
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("private key"),
        )
        .expect("token signs")
    }

    #[test]
    fn workload_header_requires_true() {
        let request = Request::new(X509svidRequest {});
        let status = require_workload_header(&request).expect_err("missing header is rejected");
        assert_eq!(status.code(), Code::InvalidArgument);

        let mut request = Request::new(X509svidRequest {});
        request.metadata_mut().insert(
            "workload.spiffe.io",
            "false".parse().expect("valid metadata"),
        );
        let status = require_workload_header(&request).expect_err("false header is rejected");
        assert_eq!(status.code(), Code::InvalidArgument);

        request.metadata_mut().insert(
            "workload.spiffe.io",
            "true".parse().expect("valid metadata"),
        );
        require_workload_header(&request).expect("true header is accepted");
    }

    #[test]
    fn workload_header_rejects_duplicates_binary_and_malformed_values() {
        fn request_with_values(values: &[&str]) -> Request<X509svidRequest> {
            let mut request = Request::new(X509svidRequest {});
            for value in values {
                request.metadata_mut().append(
                    "workload.spiffe.io",
                    value.parse().expect("valid metadata value"),
                );
            }
            request
        }

        const SECRET_METADATA: &str = "Authorization: Bearer vault-token-s.123";
        for values in [
            &["true", "true"][..],
            &["false", "true"],
            &["true", "false"],
            &["TRUE"],
            &["True"],
            &[" true"],
            &["true "],
            &["\ttrue"],
            &[SECRET_METADATA],
            &[&"a".repeat(16 * 1024)],
        ] {
            let status = require_workload_header(&request_with_values(values))
                .expect_err("malformed workload header is rejected");
            assert_eq!(status.code(), Code::InvalidArgument);
            assert_eq!(
                status.message(),
                "SPIFFE Workload API requests require workload.spiffe.io=true"
            );
            assert!(!status.message().contains("vault-token-s.123"));
        }

        let mut binary_only = Request::new(X509svidRequest {});
        binary_only.metadata_mut().insert_bin(
            "workload.spiffe.io-bin",
            tonic::metadata::MetadataValue::from_bytes(b"true"),
        );
        let status = require_workload_header(&binary_only)
            .expect_err("binary metadata key does not satisfy string gate");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn workload_api_methods_reject_missing_header_consistently() {
        let (service, _backend) = service();

        let status = service
            .fetch_x509svid(Request::new(X509svidRequest {}))
            .await
            .err()
            .expect("missing x509 svid header rejected");
        assert_eq!(status.code(), Code::InvalidArgument);

        let status = service
            .fetch_x509_bundles(Request::new(X509BundlesRequest {}))
            .await
            .err()
            .expect("missing x509 bundles header rejected");
        assert_eq!(status.code(), Code::InvalidArgument);

        let status = service
            .fetch_jwtsvid(Request::new(JwtsvidRequest {
                audience: vec!["vault".to_string()],
                spiffe_id: String::new(),
            }))
            .await
            .expect_err("missing jwt svid header rejected");
        assert_eq!(status.code(), Code::InvalidArgument);

        let status = service
            .fetch_jwt_bundles(Request::new(JwtBundlesRequest {}))
            .await
            .err()
            .expect("missing jwt bundles header rejected");
        assert_eq!(status.code(), Code::InvalidArgument);

        let status = service
            .validate_jwtsvid(Request::new(ValidateJwtsvidRequest {
                audience: "vault".to_string(),
                svid: valid_jwt_svid(
                    "vault",
                    jsonwebtoken::get_current_timestamp().saturating_add(300),
                ),
            }))
            .await
            .expect_err("missing validate header rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn fetch_jwtsvid_templates_default_spiffe_id() {
        let (service, backend) = service();
        let response = service
            .fetch_jwtsvid(jwt_request(9100, "", vec!["vault"]))
            .await
            .expect("fetch jwt-svid")
            .into_inner();
        assert_eq!(response.svids.len(), 1);
        let svid = response.svids.first().expect("one svid");
        assert_eq!(svid.spiffe_id, "spiffe://example.org/svc-api");
        let claims = token_claims(&svid.svid);
        assert_eq!(claims["iss"], "spiffe://example.org/basil");
        assert_eq!(claims["sub"], "spiffe://example.org/svc-api");
        assert_eq!(claims["aud"], "vault");
        assert_eq!(
            backend.sign_calls.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    /// basil-gymz coherence: `fetch_jwtsvid` pins ONE generation for the whole
    /// RPC: the issuer/mint authorization AND the templated SPIFFE id render
    /// against the same snapshot. After a reload swaps the generation (here, the
    /// config renames uid 9100), a later RPC templates the id against the NEW
    /// generation; the swap is observed via the single pin, and the issuer choice
    /// and templated id stay coherent (one snapshot, never a mix). Before the fix
    /// `requested_or_templated_spiffe_id` loaded a SECOND fresh snapshot, so a
    /// reload between the two loads could template against a different generation.
    #[tokio::test]
    async fn fetch_jwtsvid_templates_against_reloaded_generation_coherently() {
        // Reload policy: same catalog (routing shape unchanged), config renames
        // uid 9100 → "renamed".
        const RENAMED_POLICY: &str = r#"{
          "schemaVersion": 2,
          "subjects": {
            "svc.api": { "allOf": [ { "kind": "unix", "uid": 9100 } ] }
          },
          "roles": { "minter": ["mint"], "validator": ["validate"] },
          "rules": [
            { "id": "allow-svc-jwt", "subjects": ["svc.api"], "action": ["role:minter"], "target": ["spire.jwt"] },
            { "id": "allow-svc-x509", "subjects": ["svc.api"], "action": ["role:minter"], "target": ["spire.x509"] },
            { "id": "allow-svc-validate", "subjects": ["svc.api"], "action": ["role:validator"], "target": ["spire.jwt"] }
          ],
          "config": { "names": { "users": { "9100": "renamed" }, "groups": {} }, "memberships": {} }
        }"#;

        let (service, _backend) = service();

        // Generation 1: uid 9100 → "svc-api".
        let before = service
            .fetch_jwtsvid(jwt_request(9100, "", vec!["vault"]))
            .await
            .expect("gen 1 fetch jwt-svid")
            .into_inner();
        assert_eq!(
            before.svids.first().expect("svid").spiffe_id,
            "spiffe://example.org/svc-api"
        );

        // Reload: build the new generation from the renamed-config policy and
        // swap it in (the routing shape is unchanged, so this is reloadable).
        let (cat, pol, cfg, _) = load(CATALOG, RENAMED_POLICY).expect("reload fixture loads");
        let next = crate::state::Generation::new(2, std::sync::Arc::new(cat), pol, cfg);
        service.state.swap_generation(std::sync::Arc::new(next));
        assert_eq!(service.state.active_generation_id(), 2);

        // Generation 2: the same RPC now templates against the reloaded config.
        let after = service
            .fetch_jwtsvid(jwt_request(9100, "", vec!["vault"]))
            .await
            .expect("gen 2 fetch jwt-svid")
            .into_inner();
        let svid = after.svids.first().expect("svid");
        assert_eq!(svid.spiffe_id, "spiffe://example.org/renamed");
        // The minted token's subject matches the templated id, so issuer + id are
        // coherent within the one pinned generation.
        let claims = token_claims(&svid.svid);
        assert_eq!(claims["sub"], "spiffe://example.org/renamed");
        assert_eq!(claims["iss"], "spiffe://example.org/basil");
    }

    /// basil-zq6w: after a reload, `BackendManager` still owns the startup
    /// catalog, but SPIFFE issuer discovery must follow the serving generation's
    /// labels. Routing through `manager.resolve()` stays correct because the
    /// reload guard keeps backend/path/engine/keyType stable; candidate discovery
    /// is the label-sensitive part.
    #[tokio::test]
    async fn fetch_jwtsvid_discovers_issuer_from_reloaded_generation_catalog() {
        let (service, _backend) = service();
        assert_eq!(service.state.active_generation_id(), 1);

        let reloaded_catalog = CATALOG
            .replace("trust_domain=example.org", "trust_domain=other.org")
            .replace(
                "spiffe_id=spiffe://example.org/basil",
                "spiffe_id=spiffe://other.org/basil",
            );
        let (cat, pol, cfg, warnings) =
            load(&reloaded_catalog, POLICY).expect("label-only reload fixture loads");
        assert!(warnings.is_empty());
        let next = crate::state::Generation::new(2, std::sync::Arc::new(cat), pol, cfg);
        service.state.swap_generation(std::sync::Arc::new(next));

        let response = service
            .fetch_jwtsvid(jwt_request(
                9100,
                "spiffe://other.org/svc-api",
                vec!["vault"],
            ))
            .await
            .expect("reloaded trust-domain issuer is discoverable")
            .into_inner();
        let svid = response.svids.first().expect("svid");
        assert_eq!(svid.spiffe_id, "spiffe://other.org/svc-api");
        let claims = token_claims(&svid.svid);
        assert_eq!(claims["iss"], "spiffe://other.org/basil");
        assert_eq!(claims["sub"], "spiffe://other.org/svc-api");
    }

    #[tokio::test]
    async fn fetch_x509svid_streams_initial_svid_set() {
        use futures::StreamExt as _;

        let (service, backend) = service();
        let mut stream = service
            .fetch_x509svid(x509_request(9100))
            .await
            .expect("fetch x509-svid")
            .into_inner();
        let response = stream
            .next()
            .await
            .expect("initial response")
            .expect("initial response ok");
        assert_eq!(response.svids.len(), 1);
        let svid = response.svids.first().expect("one svid");
        assert_eq!(svid.spiffe_id, "spiffe://example.org/svc-api");
        assert_eq!(svid.x509_svid, b"leafissuer");
        assert_eq!(svid.x509_svid_key, b"private-key");
        assert_eq!(svid.bundle, b"bundle");
        assert_eq!(
            backend.x509_calls.lock().expect("calls lock").as_slice(),
            ["spiffe://example.org/svc-api"]
        );
    }

    #[tokio::test]
    async fn fetch_x509svid_honors_configured_ttl() {
        use futures::StreamExt as _;

        let (service, backend) = service_with_limits(BrokerLimits {
            svid_ttl_secs: 4,
            ..BrokerLimits::default()
        });
        let mut stream = service
            .fetch_x509svid(x509_request(9100))
            .await
            .expect("fetch x509-svid")
            .into_inner();
        let response = stream
            .next()
            .await
            .expect("initial response")
            .expect("initial response ok");
        assert_eq!(response.svids.len(), 1);
        assert_eq!(
            backend
                .expected_x509_ttl
                .load(std::sync::atomic::Ordering::SeqCst),
            4
        );
    }

    #[test]
    fn x509_refresh_interval_is_half_ttl_with_floor() {
        let plan = X509IssuePlan {
            key_name: "pki/issue/workload".to_string(),
            spiffe_id: "spiffe://example.org/svc-api".to_string(),
            trust_domain: "example.org".to_string(),
            ttl_seconds: DEFAULT_SVID_TTL_SECS,
        };
        assert_eq!(x509_refresh_after_secs(&plan), DEFAULT_SVID_TTL_SECS / 2);

        let short_plan = X509IssuePlan {
            ttl_seconds: 1,
            ..plan
        };
        assert_eq!(x509_refresh_after_secs(&short_plan), 1);
    }

    #[tokio::test]
    async fn fetch_x509svid_denies_unauthorized_uid_before_issuing() {
        let (service, backend) = service();
        let Err(status) = service.fetch_x509svid(x509_request(7777)).await else {
            panic!("unauthorized uid accepted");
        };
        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(backend.x509_calls.lock().expect("calls lock").is_empty());
    }

    #[tokio::test]
    async fn fetch_x509_bundles_streams_initial_bundle_map() {
        use futures::StreamExt as _;

        let (service, _backend) = service();
        let mut stream = service
            .fetch_x509_bundles(x509_bundles_request())
            .await
            .expect("fetch x509 bundles")
            .into_inner();
        let response = stream
            .next()
            .await
            .expect("initial response")
            .expect("initial response ok");
        assert_eq!(
            response.bundles.get("spiffe://example.org"),
            Some(&b"bundleissuer".to_vec())
        );
        assert_eq!(response.crl, vec![b"crl".to_vec()]);
    }

    #[tokio::test]
    async fn fetch_x509_bundles_pushes_on_bundle_change() {
        use futures::StreamExt as _;

        let (service, _backend) = service();
        let events = service.state.events().clone();
        let mut stream = service
            .fetch_x509_bundles(x509_bundles_request())
            .await
            .expect("fetch x509 bundles")
            .into_inner();
        let _initial = stream.next().await.expect("initial response");
        events.bundle_changed("example.org");
        let response = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("refresh response")
            .expect("stream item")
            .expect("refresh response ok");
        assert!(response.bundles.contains_key("spiffe://example.org"));
    }

    #[tokio::test]
    async fn fetch_jwt_bundles_streams_initial_jwks_map() {
        use futures::StreamExt as _;

        let (service, _backend) = service();
        let mut stream = service
            .fetch_jwt_bundles(jwt_bundles_request())
            .await
            .expect("fetch jwt bundles")
            .into_inner();
        let response = stream
            .next()
            .await
            .expect("initial response")
            .expect("initial response ok");
        let jwks = response
            .bundles
            .get("spiffe://example.org")
            .expect("jwt bundle");
        let jwks: serde_json::Value = serde_json::from_slice(jwks).expect("jwks json");
        // SPIFFE JWT-SVID profile issuer: an RSA key published as RS256 (the
        // catalog rejects an EdDSA/ed25519 JWT-SVID issuer at load, basil-6o4).
        assert_eq!(jwks["keys"][0]["kty"], "RSA");
        assert_eq!(jwks["keys"][0]["alg"], "RS256");
        assert!(jwks["keys"][0]["n"].is_string());
        assert!(jwks["keys"][0]["e"].is_string());
    }

    #[tokio::test]
    async fn fetch_jwt_bundles_pushes_on_issuer_rotation() {
        use futures::StreamExt as _;

        let (service, _backend) = service();
        let events = service.state.events().clone();
        let mut stream = service
            .fetch_jwt_bundles(jwt_bundles_request())
            .await
            .expect("fetch jwt bundles")
            .into_inner();
        let _initial = stream.next().await.expect("initial response");
        events.key_rotated("spire.jwt", 2);
        let response = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("refresh response")
            .expect("stream item")
            .expect("refresh response ok");
        assert!(response.bundles.contains_key("spiffe://example.org"));
    }

    #[tokio::test]
    async fn validate_jwtsvid_returns_spiffe_id_and_claims() {
        let (service, _backend) = service();
        let token = valid_jwt_svid(
            "vault",
            jsonwebtoken::get_current_timestamp().saturating_add(300),
        );
        let response = service
            .validate_jwtsvid(validate_request(9100, "vault", token))
            .await
            .expect("valid token")
            .into_inner();
        assert_eq!(response.spiffe_id, "spiffe://example.org/svc-api");
        let claims = response.claims.expect("claims");
        assert_eq!(
            claims
                .fields
                .get("role")
                .and_then(|value| value.kind.as_ref()),
            Some(&prost_types::value::Kind::StringValue("api".to_string()))
        );
    }

    #[tokio::test]
    async fn validate_jwtsvid_rejects_active_revoked_jti() {
        let (service, _backend) = service();
        service
            .state
            .revoke_jwt_svid(
                "example.org",
                "test-jti",
                jsonwebtoken::get_current_timestamp().saturating_add(300),
            )
            .await
            .expect("revoked jti stored");
        let token = valid_jwt_svid(
            "vault",
            jsonwebtoken::get_current_timestamp().saturating_add(300),
        );
        let status = service
            .validate_jwtsvid(validate_request(9100, "vault", token))
            .await
            .expect_err("revoked jti rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "JWT-SVID validation failed");
    }

    #[tokio::test]
    async fn validate_jwtsvid_allows_expired_revoked_jti_entry() {
        let (service, _backend) = service();
        service
            .state
            .revoke_jwt_svid(
                "example.org",
                "test-jti",
                jsonwebtoken::get_current_timestamp().saturating_sub(1),
            )
            .await
            .expect("expired jti ignored");
        let token = valid_jwt_svid(
            "vault",
            jsonwebtoken::get_current_timestamp().saturating_add(300),
        );
        let response = service
            .validate_jwtsvid(validate_request(9100, "vault", token))
            .await
            .expect("expired deny-list entry does not reject")
            .into_inner();
        assert_eq!(response.spiffe_id, "spiffe://example.org/svc-api");
    }

    #[tokio::test]
    async fn validate_jwtsvid_is_policy_gated() {
        let (service, _backend) = service();
        let token = valid_jwt_svid(
            "vault",
            jsonwebtoken::get_current_timestamp().saturating_add(300),
        );
        let status = service
            .validate_jwtsvid(validate_request(7777, "vault", token))
            .await
            .expect_err("unauthorized validator rejected");
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn validate_jwtsvid_rejects_wrong_audience() {
        let (service, _backend) = service();
        let token = valid_jwt_svid(
            "vault",
            jsonwebtoken::get_current_timestamp().saturating_add(300),
        );
        let status = service
            .validate_jwtsvid(validate_request(9100, "other", token))
            .await
            .expect_err("wrong audience rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "JWT-SVID validation failed");
    }

    #[tokio::test]
    async fn validate_jwtsvid_rejects_expired_token() {
        let (service, _backend) = service();
        let token = valid_jwt_svid(
            "vault",
            jsonwebtoken::get_current_timestamp().saturating_sub(120),
        );
        let status = service
            .validate_jwtsvid(validate_request(9100, "vault", token))
            .await
            .expect_err("expired token rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "JWT-SVID validation failed");
    }

    #[tokio::test]
    async fn validate_jwtsvid_rejects_bad_signature() {
        let (service, _backend) = service();
        let mut token = valid_jwt_svid(
            "vault",
            jsonwebtoken::get_current_timestamp().saturating_add(300),
        );
        token.push('x');
        let status = service
            .validate_jwtsvid(validate_request(9100, "vault", token))
            .await
            .expect_err("bad signature rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "JWT-SVID validation failed");
    }

    #[tokio::test]
    async fn fetch_jwtsvid_rejects_malformed_spiffe_ids_and_audiences() {
        let (service, _backend) = service();
        for requested in [
            "example.org/no-scheme",
            "spiffe://example.org",
            "spiffe://example.org/",
            "spiffe://example.org/svc api",
        ] {
            let status = service
                .fetch_jwtsvid(jwt_request(9100, requested, vec!["vault"]))
                .await
                .expect_err("malformed requested SPIFFE ID rejected");
            assert_eq!(status.code(), Code::InvalidArgument);
        }

        let status = service
            .fetch_jwtsvid(jwt_request(
                9100,
                "spiffe://other.org/svc-api",
                vec!["vault"],
            ))
            .await
            .expect_err("out-of-domain requested SPIFFE ID rejected");
        assert_eq!(status.code(), Code::PermissionDenied);

        for audience in ["", " ", "\t", "\n"] {
            let status = service
                .fetch_jwtsvid(jwt_request(9100, "", vec![audience]))
                .await
                .expect_err("blank audience rejected");
            assert_eq!(status.code(), Code::InvalidArgument);
            assert_eq!(
                status.message(),
                "FetchJWTSVID requires a non-empty audience"
            );
        }
    }

    #[tokio::test]
    async fn validate_jwtsvid_rejects_malformed_inputs_consistently() {
        let (service, _backend) = service();
        for (audience, token) in [
            ("", valid_jwt_svid("vault", 300)),
            (" ", valid_jwt_svid("vault", 300)),
            ("vault", String::new()),
            ("vault", "not.a.jwt".to_string()),
        ] {
            let status = service
                .validate_jwtsvid(validate_request(9100, audience, token))
                .await
                .expect_err("malformed validation input rejected");
            assert_eq!(status.code(), Code::InvalidArgument);
        }
    }

    #[test]
    fn workload_api_upstream_errors_omit_secret_bearing_details() {
        let canaries = [
            "vault-token-s.123",
            "Authorization: Bearer secret",
            "/run/credentials/basil/passphrase",
            "-----BEGIN PRIVATE KEY-----",
            "upstream-response-body-with-credential",
        ];
        let statuses = [
            mint_status(&crate::minter::GenericMintError::Backend(
                crate::backend::BackendError::Backend(canaries[4].to_string()),
            )),
            x509_issue_status(&crate::manager::ManagerError::Backend(
                crate::backend::BackendError::Transport(canaries[1].to_string()),
            )),
            upstream_unavailable(),
        ];
        for status in statuses {
            assert_eq!(status.code(), Code::Unavailable);
            for canary in canaries {
                assert!(
                    !status.message().contains(canary),
                    "Workload API status leaked secret canary `{canary}`"
                );
            }
        }
    }

    #[tokio::test]
    async fn fetch_jwtsvid_accepts_explicit_caller_identity() {
        let (service, _backend) = service();
        let response = service
            .fetch_jwtsvid(jwt_request(
                9100,
                "spiffe://example.org/svc-api",
                vec!["vault", "nats"],
            ))
            .await
            .expect("fetch jwt-svid")
            .into_inner();
        assert_eq!(response.svids.len(), 2);
        assert!(
            response
                .svids
                .iter()
                /* ubs constant time equality check is not needed here */
                /* ubs:ignore */
                .all(|svid| svid.spiffe_id == "spiffe://example.org/svc-api")
        );
    }

    #[tokio::test]
    async fn fetch_jwtsvid_rejects_explicit_same_domain_impersonation() {
        let (service, _backend) = service();
        let status = service
            .fetch_jwtsvid(jwt_request(
                9100,
                "spiffe://example.org/custom",
                vec!["vault", "nats"],
            ))
            .await
            .expect_err("impersonation denied");
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn fetch_jwtsvid_requires_audience() {
        let (service, _backend) = service();
        let status = service
            .fetch_jwtsvid(jwt_request(9100, "", vec![]))
            .await
            .expect_err("missing audience rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn fetch_jwtsvid_denies_unauthorized_uid_before_signing() {
        let (service, backend) = service();
        let status = service
            .fetch_jwtsvid(jwt_request(7777, "", vec!["vault"]))
            .await
            .expect_err("unauthorized uid rejected");
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(
            backend.sign_calls.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[test]
    fn svid_alg_selects_profile_algs_and_fails_closed_otherwise() {
        assert_eq!(
            svid_alg(Some(KeyAlgorithm::Rsa2048)).expect("rsa is a JWT-SVID alg"),
            crate::minter::SvidAlg::Rs256
        );
        assert_eq!(
            svid_alg(Some(KeyAlgorithm::EcdsaP256)).expect("p256 is a JWT-SVID alg"),
            crate::minter::SvidAlg::Es256
        );
        assert_eq!(
            svid_alg(Some(KeyAlgorithm::EcdsaP384)).expect("p384 is a JWT-SVID alg"),
            crate::minter::SvidAlg::Es384
        );
        // EdDSA/Ed25519 is rejected at catalog load, so this is the runtime
        // backstop: it must fail closed with FailedPrecondition (never panic).
        for key_type in [
            None,
            Some(KeyAlgorithm::Ed25519),
            Some(KeyAlgorithm::Ed25519Nkey),
            Some(KeyAlgorithm::EcdsaP521),
            Some(KeyAlgorithm::Aes256Gcm),
            Some(KeyAlgorithm::X25519),
        ] {
            let status = svid_alg(key_type).expect_err("non-profile alg is rejected");
            assert_eq!(status.code(), Code::FailedPrecondition);
        }
    }
}
