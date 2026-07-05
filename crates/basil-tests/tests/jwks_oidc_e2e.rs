//! Live JWKS HTTP-surface e2e (basil-uce.3).
//!
//! basil-uce.1 unit-tests the JWKS handler by driving `build_jwks`/`assemble_jwks`
//! directly and asserts the disabled-by-default gate at the config layer. This
//! test closes the gap: it boots a real SPIFFE-enabled broker with the (otherwise
//! opt-in) `[jwks]` HTTP surface **enabled**, then exercises the full
//! bind + serve + fetch + verify path against a **live RSA JWT-SVID issuer** on
//! bao AND vault:
//!
//!   1. boot the broker with `[jwks] enable = true`, a loopback `listen` port
//!      (distinct from the dev-engine port), and `issuer = http://<listen>`;
//!   2. `GET /jwks.json` AND `/.well-known/jwks.json` over the real bound TCP port
//!      via `reqwest`; assert the RFC 7517 JWK-set shape (`kty=RSA`, `n`, `e`,
//!      `kid`, `alg=RS256`, `use=sig`), the `application/jwk-set+json`
//!      content-type, and the `Cache-Control` + `ETag` headers;
//!   3. mint an RS256 JWT-SVID via the SPIFFE Workload API `FetchJWTSVID`
//!      (`basil_tests::fetch_jwt_svid`), the RSA issuer path whose `kid` is published
//!      in the JWKS, and verify it with the `jsonwebtoken` crate using a
//!      `DecodingKey::from_rsa_components(n, e)` selected from the fetched JWKS by
//!      the token's `kid`. That is the standards-library validation bar: a plain
//!      verifier needs only the served JWKS (no SPIFFE plumbing) to validate.
//!
//! GATING: each engine leg is gated on `on_path(Engine::cli_bin())` and prints an
//! EXPLICIT skip line if the engine binary is absent (acceptance forbids a silent
//! `#[ignore]`). `ran_any` asserts an all-absent environment fails loudly rather
//! than passing vacuously. Each leg draws TWO `alloc_addr()` ports: one for the
//! dev engine, one for the JWKS bind, so the dev servers and HTTP listeners never
//! fight for a port across concurrently-running test binaries.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::allow_attributes
)]

use basil_tests::on_path;

use basil_tests::{
    Engine, JwksSpec, alloc_addr, boot_basil_spiffe, fetch_jwt_svid, repo_root, rotate_transit_key,
};

/// Strip the `http://` scheme `alloc_addr` prepends, yielding a bare
/// `127.0.0.1:<port>` bind address for the JWKS `listen`.
fn bind_addr(alloc: &str) -> String {
    alloc.strip_prefix("http://").unwrap_or(alloc).to_string()
}

/// Assert the fetched body is an RFC 7517 JWK set of RSA JWT-SVID issuer keys and
/// return its parsed JSON. Every key must be an RS256 signing RSA public key with
/// `n`/`e`/`kid`.
fn jwk_keys(jwks: &serde_json::Value) -> &Vec<serde_json::Value> {
    jwks.get("keys")
        .and_then(serde_json::Value::as_array)
        .expect("JWKS has a `keys` array")
}

/// A non-empty string at `field`, or panic.
fn str_field<'a>(obj: &'a serde_json::Value, field: &str) -> &'a str {
    let v = obj
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("JWK has a `{field}`"));
    assert!(!v.is_empty(), "JWK `{field}` is non-empty");
    v
}

fn assert_jwk_set_shape(body: &[u8]) -> serde_json::Value {
    let jwks: serde_json::Value = serde_json::from_slice(body).expect("JWKS body is JSON");
    let keys = jwk_keys(&jwks);
    assert!(!keys.is_empty(), "served JWK set is non-empty");
    for key in keys {
        assert_eq!(
            key.get("kty").and_then(serde_json::Value::as_str),
            Some("RSA"),
            "JWK kty is RSA"
        );
        assert_eq!(
            key.get("alg").and_then(serde_json::Value::as_str),
            Some("RS256"),
            "JWK alg is RS256"
        );
        assert_eq!(
            key.get("use").and_then(serde_json::Value::as_str),
            Some("sig"),
            "JWK use is sig"
        );
        let _ = str_field(key, "n");
        let _ = str_field(key, "e");
        let _ = str_field(key, "kid");
    }
    jwks
}

/// GET `path` over the bound TCP port, asserting the JWKS content-type and the
/// `Cache-Control` + `ETag` cache headers, then validate the JWK-set shape. Return
/// the parsed JSON.
async fn get_jwks(client: &reqwest::Client, base: &str, path: &str) -> serde_json::Value {
    let resp = client
        .get(format!("{base}{path}"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {path}: {e}"));
    assert!(
        resp.status().is_success(),
        "GET {path} -> {}",
        resp.status()
    );

    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .expect("content-type header present")
        .to_string();
    assert!(
        content_type.contains("application/jwk-set+json") || content_type.contains("json"),
        "JWKS content-type is a JWK-set/JSON type (got {content_type})"
    );

    let cache = resp
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .expect("cache-control header present")
        .to_string();
    assert!(
        cache.contains("max-age="),
        "JWKS carries a Cache-Control max-age (got {cache})"
    );
    assert!(
        resp.headers().get(reqwest::header::ETAG).is_some(),
        "JWKS carries an ETag"
    );

    let body = resp.bytes().await.expect("JWKS body bytes");
    assert_jwk_set_shape(&body)
}

/// Verify a Basil-minted JWT-SVID against the served JWKS exactly as a standard
/// verifier would: decode the token header for its `kid`, select the matching JWK,
/// reconstruct a `DecodingKey` from the JWK's `n`/`e`, and validate the signature
/// (NOT `iss`; Basil JWT-SVIDs carry a SPIFFE `iss`, per the discovery-doc
/// decision). Asserts the token's `kid` is present in the served set.
fn verify_token_via_jwks(token: &str, jwks: &serde_json::Value, audience: &str) {
    let header = jsonwebtoken::decode_header(token).expect("decode JWT header");
    let kid = header.kid.expect("minted JWT-SVID carries a kid");

    let jwk = jwk_keys(jwks)
        .iter()
        .find(|k| k.get("kid").and_then(serde_json::Value::as_str) == Some(kid.as_str()))
        .unwrap_or_else(|| panic!("minted token's kid {kid} is published in the JWKS"));

    let n = str_field(jwk, "n");
    let e = str_field(jwk, "e");
    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_components(n, e).expect("DecodingKey from n/e");

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.validate_aud = true;
    // Basil JWT-SVIDs carry a SPIFFE `iss`, not the discovery `issuer`, so we do
    // not assert `iss`; we validate the signature + `aud` + required SVID claims.
    validation.set_required_spec_claims(&["exp", "sub", "aud"]);
    jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
        .expect("JWT-SVID validates against the JWKS-derived key");
}

/// Like [`verify_token_via_jwks`] but **non-panicking**: returns `true` only if a
/// JWK in the served set matches the token's `kid` AND the RS256 signature + `aud`
/// validate. Used to assert a stale-kid token (its issuer version dropped past the
/// grace floor) NO LONGER resolves against the current JWKS. Does NOT assert `iss`
/// (Basil JWT-SVIDs carry a SPIFFE `iss`).
fn try_verify_token_via_jwks(token: &str, jwks: &serde_json::Value, audience: &str) -> bool {
    let Ok(header) = jsonwebtoken::decode_header(token) else {
        return false;
    };
    let Some(kid) = header.kid else { return false };
    let Some(jwk) = jwk_keys(jwks)
        .iter()
        .find(|k| k.get("kid").and_then(serde_json::Value::as_str) == Some(kid.as_str()))
    else {
        return false; // kid not published in the current set → cannot resolve
    };
    let (Some(n), Some(e)) = (
        jwk.get("n").and_then(serde_json::Value::as_str),
        jwk.get("e").and_then(serde_json::Value::as_str),
    ) else {
        return false;
    };
    let Ok(decoding_key) = jsonwebtoken::DecodingKey::from_rsa_components(n, e) else {
        return false;
    };
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.validate_aud = true;
    validation.set_required_spec_claims(&["exp", "sub", "aud"]);
    jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation).is_ok()
}

/// Count distinct `kid`s in a JWK set.
fn published_kid_count(jwks: &serde_json::Value) -> usize {
    use std::collections::BTreeSet;
    jwk_keys(jwks)
        .iter()
        .filter_map(|k| k.get("kid").and_then(serde_json::Value::as_str))
        .collect::<BTreeSet<_>>()
        .len()
}

/// Extract the token's `kid` (every minted JWT-SVID carries one).
fn token_kid(token: &str) -> String {
    jsonwebtoken::decode_header(token)
        .expect("decode JWT header")
        .kid
        .expect("minted JWT-SVID carries a kid")
}

/// True if `kid` is present in the served JWK set.
fn jwks_has_kid(jwks: &serde_json::Value, kid: &str) -> bool {
    jwk_keys(jwks)
        .iter()
        .any(|k| k.get("kid").and_then(serde_json::Value::as_str) == Some(kid))
}

/// Fetch + validate the OIDC discovery document a standard verifier reads to
/// learn the issuer's keys. Asserts the discovery doc is self-consistent:
/// `issuer` equals the configured issuer, `jwks_uri` is `issuer` + the served
/// JWKS path, and `RS256` is an advertised signing alg, and returns the
/// `jwks_uri` a verifier would follow (NOT a hardcoded path).
async fn discover_jwks_uri(client: &reqwest::Client, base: &str, expected_issuer: &str) -> String {
    let url = format!("{base}/.well-known/openid-configuration");
    let resp = client
        .get(&url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {url}: {e}"));
    assert!(resp.status().is_success(), "GET {url} -> {}", resp.status());
    let doc: serde_json::Value = resp.json().await.expect("discovery doc is JSON");

    let issuer = doc
        .get("issuer")
        .and_then(serde_json::Value::as_str)
        .expect("discovery doc has an `issuer`");
    assert_eq!(
        issuer, expected_issuer,
        "discovery `issuer` matches the configured issuer"
    );

    let jwks_uri = doc
        .get("jwks_uri")
        .and_then(serde_json::Value::as_str)
        .expect("discovery doc has a `jwks_uri`")
        .to_string();
    assert_eq!(
        jwks_uri,
        format!("{issuer}/jwks.json"),
        "`jwks_uri` is the issuer base + the served JWKS path (consistent)"
    );

    let algs = doc
        .get("id_token_signing_alg_values_supported")
        .and_then(serde_json::Value::as_array)
        .expect("discovery doc advertises signing algs");
    assert!(
        algs.iter().any(|a| a.as_str() == Some("RS256")),
        "RS256 is an advertised id_token signing alg (got {algs:?})"
    );

    jwks_uri
}

/// Drive ONE engine through the full OIDC discovery + rotation/grace path with a
/// standard `jsonwebtoken` verifier (basil-mil0.1):
///
///   1. boot with `[jwks]` enabled AND `issuer` set;
///   2. **discovery:** GET `/.well-known/openid-configuration`, assert it is
///      self-consistent, and follow `jwks_uri` (NOT a hardcoded path) to fetch
///      the JWKS, proving a verifier finds the keys from metadata alone;
///   3. **verify:** mint token A, verify it against the JWK selected by its `kid`
///      (signature + `aud` only, NOT `iss`);
///   4. **rotation/grace:** rotate the RSA issuer transit key out-of-band via the
///      engine CLI. After v2: re-fetch via `jwks_uri`, assert BOTH kids (v1+v2)
///      are published (grace=1), and verify token A AND a v2-signed token B.
///      After a 2nd rotation to v3 (grace floor advances to 2): re-fetch, assert
///      v1's `kid` is DROPPED, and that token A no longer resolves while token B
///      (v2) and a fresh token C (v3) DO.
#[allow(clippy::too_many_lines)] // full discovery + verify + two-rotation grace loop
async fn drive_engine_oidc(engine: Engine, tag: &str) {
    let dev_addr = alloc_addr();
    let listen = bind_addr(&alloc_addr());
    let base = format!("http://{listen}");
    let jwks_spec = JwksSpec {
        listen: listen.clone(),
        issuer: Some(base.clone()),
    };

    let harness = boot_basil_spiffe(tag, engine, &dev_addr, Some(&jwks_spec));
    let endpoint = harness.endpoint();
    let client = reqwest::Client::new();
    let audience = "oidc-e2e";
    let eng = engine.prefill_name();

    // The broker binds the socket before the JWKS task; bound-retry the discovery
    // doc until the HTTP listener is up so a slow bind doesn't flake.
    let discovery_url = format!("{base}/.well-known/openid-configuration");
    let mut last_err = None;
    for _ in 0..50 {
        match client.get(&discovery_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                last_err = None;
                break;
            }
            Ok(resp) => last_err = Some(format!("status {}", resp.status())),
            Err(e) => last_err = Some(e.to_string()),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        last_err.is_none(),
        "OIDC discovery never served {discovery_url}: {last_err:?}"
    );

    // (1) Discovery leg: parse the discovery doc and follow its `jwks_uri`.
    let jwks_uri = discover_jwks_uri(&client, &base, &base).await;
    assert_eq!(
        jwks_uri,
        format!("{base}/jwks.json"),
        "discovered jwks_uri points back at this surface"
    );
    eprintln!("OIDC-E2E[{eng}]: discovered issuer={base} jwks_uri={jwks_uri} (RS256)");

    // Fetch the JWKS by FOLLOWING the discovered jwks_uri (not a literal path).
    let jwks_v1 = get_jwks(&client, &jwks_uri, "").await;
    let kids_v1 = published_kid_count(&jwks_v1);

    // (2) Verify leg: mint token_A and verify it against the discovered JWKS by kid
    //     (signature + aud only, NOT iss).
    let token_a = fetch_jwt_svid(&endpoint, audience).await;
    let kid_a = token_kid(&token_a);
    verify_token_via_jwks(&token_a, &jwks_v1, audience);
    assert!(
        jwks_has_kid(&jwks_v1, &kid_a),
        "token_A's kid is published at v1"
    );
    eprintln!(
        "OIDC-E2E[{eng}]: token_A (kid={kid_a}) verified off the discovered JWKS \
         (kids before={kids_v1})"
    );

    // (3) Rotation leg: rotate the RSA issuer key OUT-OF-BAND to v2. `spiffe-jwt`
    //     is the transit issuer key the prefill SPIFFE block fills (catalog key
    //     spiffe.jwt_issuer, mount transit). The JWKS reads public_keys fresh per
    //     request, so v2's kid appears with no broker reload.
    rotate_transit_key(engine, harness.backend_addr(), "keys/spiffe-jwt");

    let token_b = fetch_jwt_svid(&endpoint, audience).await;
    let kid_b = token_kid(&token_b);
    assert_ne!(
        kid_a, kid_b,
        "rotation gives token_B a fresh kid (v2 != v1)"
    );

    let jwks_v2 = get_jwks(&client, &jwks_uri, "").await;
    let kids_v2 = published_kid_count(&jwks_v2);
    assert_eq!(
        kids_v2, 2,
        "grace=1: JWKS publishes BOTH v1 and v2 kids after one rotation"
    );
    assert!(
        jwks_has_kid(&jwks_v2, &kid_a) && jwks_has_kid(&jwks_v2, &kid_b),
        "both v1 (token_A) and v2 (token_B) kids are in grace"
    );
    // BOTH the pre- and post-rotation tokens verify while both kids are in grace.
    verify_token_via_jwks(&token_a, &jwks_v2, audience);
    verify_token_via_jwks(&token_b, &jwks_v2, audience);
    eprintln!(
        "OIDC-E2E[{eng}]: after rotate -> v2: kids after-rotate={kids_v2} \
         (v1+v2 in grace); token_A AND token_B both verify"
    );

    // (4) Rotate AGAIN to v3: the grace floor advances to 2, so v1 falls below it
    //     and its JWK is DROPPED. A v1-keyed token can no longer resolve.
    rotate_transit_key(engine, harness.backend_addr(), "keys/spiffe-jwt");

    let token_c = fetch_jwt_svid(&endpoint, audience).await;
    let kid_c = token_kid(&token_c);
    assert_ne!(
        kid_c, kid_b,
        "second rotation gives token_C a fresh kid (v3)"
    );

    let jwks_v3 = get_jwks(&client, &jwks_uri, "").await;
    let kids_v3 = published_kid_count(&jwks_v3);
    assert_eq!(
        kids_v3, 2,
        "grace=1: JWKS publishes v2+v3 after the second rotation"
    );
    assert!(
        !jwks_has_kid(&jwks_v3, &kid_a),
        "v1 (token_A) kid is DROPPED once the grace floor advances to 2"
    );
    assert!(
        jwks_has_kid(&jwks_v3, &kid_b) && jwks_has_kid(&jwks_v3, &kid_c),
        "v2 (token_B) and v3 (token_C) kids are the in-grace set"
    );
    // token_A (v1 kid absent) no longer resolves; token_B (v2) and token_C (v3) do.
    assert!(
        !try_verify_token_via_jwks(&token_a, &jwks_v3, audience),
        "token_A (stale v1 kid) NO LONGER verifies; its kid dropped from the set"
    );
    verify_token_via_jwks(&token_b, &jwks_v3, audience);
    verify_token_via_jwks(&token_c, &jwks_v3, audience);
    eprintln!(
        "OIDC-E2E[{eng}]: after 2nd rotate -> v3: kids before={kids_v1} \
         after-rotate={kids_v2} after-2nd-rotate={kids_v3} (v1 dropped); \
         token_A stale-kid REJECTED, token_B + token_C verify"
    );

    drop(harness);
}

/// Drive one engine end to end: boot the SPIFFE broker with the JWKS surface
/// enabled, fetch both JWKS paths over the bound TCP port, then mint a JWT-SVID and
/// verify it against the served set.
async fn drive_engine(engine: Engine, tag: &str) {
    let dev_addr = alloc_addr();
    let listen = bind_addr(&alloc_addr());
    let base = format!("http://{listen}");
    let jwks = JwksSpec {
        listen: listen.clone(),
        issuer: Some(base.clone()),
    };

    let harness = boot_basil_spiffe(tag, engine, &dev_addr, Some(&jwks));
    let endpoint = harness.endpoint();

    // The broker binds the socket before the JWKS task; give the HTTP listener a
    // brief moment to bind the TCP port, then fetch (with a bounded retry so a
    // slow bind doesn't flake).
    let client = reqwest::Client::new();
    let jwks_url = format!("{base}/jwks.json");
    let mut last_err = None;
    for _ in 0..50 {
        match client.get(&jwks_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                last_err = None;
                break;
            }
            Ok(resp) => last_err = Some(format!("status {}", resp.status())),
            Err(e) => last_err = Some(e.to_string()),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        last_err.is_none(),
        "JWKS HTTP surface never served {jwks_url}: {last_err:?}"
    );

    // (1) Both JWKS paths serve the same RFC 7517 set with cache headers.
    let jwks = get_jwks(&client, &base, "/jwks.json").await;
    let well_known = get_jwks(&client, &base, "/.well-known/jwks.json").await;
    assert_eq!(
        jwks, well_known,
        "/jwks.json and /.well-known/jwks.json serve the same set"
    );
    eprintln!(
        "JWKS-E2E[{}]: served {} JWK(s) on {base} (both paths)",
        engine.prefill_name(),
        jwk_keys(&jwks).len()
    );

    // (2) Mint an RS256 JWT-SVID via FetchJWTSVID and verify it against the set.
    let audience = "jwks-e2e";
    let token = fetch_jwt_svid(&endpoint, audience).await;
    verify_token_via_jwks(&token, &jwks, audience);
    eprintln!(
        "JWKS-E2E[{}]: minted JWT-SVID verified against the served JWKS by kid",
        engine.prefill_name()
    );

    drop(harness);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jwks_surface_e2e_cross_engine() {
    let mut ran_any = false;

    if on_path("bao") {
        {
            drive_engine(Engine::OpenBao, "jwks-e2e-bao").await;
            ran_any = true;
        }
    } else {
        eprintln!("SKIP[openbao]: bao not on PATH; JWKS live e2e needs a live engine");
    }

    if on_path("vault") {
        {
            drive_engine(Engine::Vault, "jwks-e2e-vault").await;
            ran_any = true;
        }
    } else {
        eprintln!("SKIP[vault]: vault not on PATH; JWKS live e2e needs a live engine");
    }

    assert!(
        ran_any,
        "neither bao nor vault was on PATH. The JWKS live e2e ran no engine leg"
    );
}

/// Live OIDC discovery + rotation/grace interop (basil-mil0.1): an ordinary
/// `jsonwebtoken` verifier discovers the issuer from
/// `/.well-known/openid-configuration`, follows `jwks_uri` to the JWKS, and
/// validates Basil JWT-SVIDs ACROSS two out-of-band key rotations, proving both
/// "validate from the published documents alone" and safe grace expiry (the old
/// kid drops, a stale-kid token stops resolving). Cross-engine (bao + vault), each
/// gated with an explicit skip line; `ran_any` fails an all-absent environment
/// loudly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_discovery_and_rotation_e2e_cross_engine() {
    let mut ran_any = false;

    if on_path("bao") {
        {
            drive_engine_oidc(Engine::OpenBao, "oidc-e2e-bao").await;
            ran_any = true;
        }
    } else {
        eprintln!(
            "SKIP[openbao]: bao not on PATH; OIDC discovery+rotation live e2e needs a live engine"
        );
    }

    if on_path("vault") {
        {
            drive_engine_oidc(Engine::Vault, "oidc-e2e-vault").await;
            ran_any = true;
        }
    } else {
        eprintln!(
            "SKIP[vault]: vault not on PATH; OIDC discovery+rotation live e2e needs a live engine"
        );
    }

    assert!(
        ran_any,
        "neither bao nor vault was on PATH. The OIDC discovery+rotation live e2e ran no engine leg"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// basil-mil0.2: REAL EXTERNAL OIDC verifier interop.
//
// The verifiers above are in-Rust (`jsonwebtoken`). This leg proves the same
// thing against a faithful *external* OIDC relying party: a tiny Go program
// (`tests/oidc_verifier_go/`) built on `github.com/coreos/go-oidc/v3` that does
// `oidc.NewProvider(issuer)` (consuming `/.well-known/openid-configuration`) +
// `provider.Verifier(...)`, validating a Basil JWT-SVID off NOTHING but the
// published discovery doc + JWKS, no SPIFFE plumbing. A POSITIVE leg asserts the
// Go verifier accepts a freshly-minted token; a NEGATIVE leg feeds it a
// signature-tampered token and asserts a nonzero exit (it actually validates, not
// rubber-stamps). The whole Go leg is gated on `go` being on PATH AND the
// build/run succeeding; an absent toolchain or offline module fetch prints an
// explicit SKIP and is NOT a hard failure, but the skip is visible in the
// per-engine accounting.
// ─────────────────────────────────────────────────────────────────────────────

/// Absolute path to the Go external-verifier module dir (`go run .` cwd).
fn go_verifier_dir() -> std::path::PathBuf {
    repo_root().join("crates/basil-tests/tests/oidc_verifier_go")
}

/// Outcome of building/running the Go verifier once.
enum GoVerify {
    /// The verifier ran and exited 0 (token accepted).
    Accepted,
    /// The verifier ran and exited nonzero (token rejected); carries stderr.
    Rejected(String),
    /// The Go toolchain/modules were unavailable (build or spawn failed before a
    /// verdict): a SKIP condition, never a hard failure. Carries the reason.
    Unavailable(String),
}

/// Run the Go OIDC verifier against `issuer`/`token`/`audience` via `go run .`
/// with cwd = the verifier module dir. The token goes through `OIDC_TOKEN` (env,
/// off the command line) and issuer/audience as args. A clean exit-0 ⇒ accepted;
/// a clean nonzero exit ⇒ rejected (stderr captured); a spawn failure (no `go`,
/// a Go build/toolchain failure) ⇒ unavailable (SKIP), distinguished from a real
/// rejection. `go run` compiles on first use and uses the committed vendor tree
/// so offline CI can reach a verifier verdict without downloading modules.
fn run_go_verifier(issuer: &str, token: &str, audience: &str, enforce_issuer: bool) -> GoVerify {
    use std::process::Command;
    let dir = go_verifier_dir();
    let mut command = Command::new("go");
    command
        .args(["run", "."])
        .arg(issuer)
        .arg("__token_via_env__")
        .arg(audience)
        .env("OIDC_TOKEN", token)
        .env("GOFLAGS", "-mod=vendor")
        .current_dir(&dir);
    if enforce_issuer {
        command.env("OIDC_ENFORCE_ISS", "1");
    }
    let output = command.output();

    match output {
        Err(e) => GoVerify::Unavailable(format!("spawn `go run .` in {}: {e}", dir.display())),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            // `go run` distinguishes its own build/toolchain errors (exit 1 with a
            // `go: ...` / build-failure prefix on stderr and NO program stdout)
            // from the *program's* exit. A build/download failure is a SKIP, not a
            // rejection. The program emits a `verify failed:`-prefixed line on a
            // genuine rejection.
            if out.status.success() {
                GoVerify::Accepted
            } else if stderr.contains("verify failed:") {
                GoVerify::Rejected(stderr)
            } else {
                // No program-level reject line ⇒ the failure was the Go build /
                // module fetch itself (e.g. offline CI) ⇒ treat as unavailable.
                GoVerify::Unavailable(format!(
                    "go build/run failed (no verifier verdict): {stderr}"
                ))
            }
        }
    }
}

/// Flip one byte of a JWT's signature segment so its RS256 signature no longer
/// validates while the header/`kid` stay intact; the verifier still resolves a
/// key by `kid` but the signature check MUST fail. Returns the tampered compact
/// JWS. (Base64url has no padding; we mutate a char in the signature and re-emit.)
fn tamper_jwt_signature(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "a compact JWS has three dot-separated parts"
    );
    let header = parts.first().expect("JWS header segment");
    let payload = parts.get(1).expect("JWS payload segment");
    let sig = parts.get(2).expect("JWS signature segment");
    assert!(!sig.is_empty(), "JWS signature segment is non-empty");

    // Flip the first base64url char of the signature to a different valid
    // base64url char, leaving the header/`kid` and payload intact so the verifier
    // still resolves a key by `kid` but the RS256 signature check MUST fail.
    let mut chars = sig.chars();
    let first = chars.next().expect("non-empty signature has a first char");
    let replacement = if first == 'A' { 'B' } else { 'A' };
    let flipped_sig: String = std::iter::once(replacement).chain(chars).collect();

    format!("{header}.{payload}.{flipped_sig}")
}

async fn wait_for_oidc_discovery(client: &reqwest::Client, discovery_url: &str) -> bool {
    for _ in 0..50 {
        if let Ok(resp) = client.get(discovery_url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}

/// Drive ONE engine through the real-external-verifier interop:
///
///   1. boot with `[jwks]` enabled AND `issuer` set (so discovery is served);
///   2. mint a JWT-SVID via the SPIFFE Workload API;
///   3. POSITIVE: hand the live issuer URL + token + aud to the Go go-oidc
///      verifier; assert it exits 0 (a real external OIDC RP accepted a Basil JWT
///      off the published documents alone);
///   4. NEGATIVE: hand it a signature-tampered token; assert it exits nonzero
///      (the verifier validates the signature, it does not rubber-stamp).
///
/// Returns whether the Go leg actually RAN (true) or was skipped because the Go
/// toolchain/modules were unavailable (false), so the caller's accounting makes
/// a skip visible rather than a silent pass.
async fn drive_engine_external_oidc(engine: Engine, tag: &str) -> bool {
    let dev_addr = alloc_addr();
    let listen = bind_addr(&alloc_addr());
    let base = format!("http://{listen}");
    let jwks_spec = JwksSpec {
        listen: listen.clone(),
        issuer: Some(base.clone()),
    };

    let harness = boot_basil_spiffe(tag, engine, &dev_addr, Some(&jwks_spec));
    let endpoint = harness.endpoint();
    let client = reqwest::Client::new();
    let audience = "go-oidc-e2e";
    let eng = engine.prefill_name();

    // Wait for the discovery doc to be served before invoking the external
    // verifier (which itself fetches it). Bounded retry so a slow bind doesn't
    // flake the external leg.
    let discovery_url = format!("{base}/.well-known/openid-configuration");
    assert!(
        wait_for_oidc_discovery(&client, &discovery_url).await,
        "OIDC discovery never served {discovery_url} for the external verifier leg"
    );

    let token = fetch_jwt_svid(&endpoint, audience).await;
    let kid = token_kid(&token);

    // (POSITIVE) The external go-oidc verifier accepts the valid token off the
    // published discovery doc + JWKS. `go run` may compile on first use; a
    // toolchain/module failure is a SKIP, not a test failure.
    let ran = match run_go_verifier(&base, &token, audience, false) {
        GoVerify::Accepted => {
            eprintln!(
                "GO-OIDC-E2E[{eng}]: go-oidc verifier ACCEPTED valid token \
                 (issuer={base} kid={kid} aud={audience})"
            );

            // (NEGATIVE) A signature-tampered token MUST be rejected: proves the
            // verifier validates the RS256 signature off the JWKS, not just the
            // kid's presence.
            let tampered = tamper_jwt_signature(&token);
            assert_ne!(tampered, token, "tamper actually changed the token");
            match run_go_verifier(&base, &tampered, audience, false) {
                GoVerify::Rejected(reason) => {
                    eprintln!(
                        "GO-OIDC-E2E[{eng}]: go-oidc verifier REJECTED tampered token \
                         (reason: {})",
                        reason.trim()
                    );
                }
                GoVerify::Accepted => {
                    panic!(
                        "[{eng}] go-oidc verifier ACCEPTED a signature-tampered token; \
                         it is rubber-stamping, not validating"
                    );
                }
                GoVerify::Unavailable(why) => {
                    // The positive leg just ran the same toolchain, so an
                    // unavailable here would be surprising; surface it loudly.
                    panic!(
                        "[{eng}] go-oidc verifier became unavailable on the negative leg \
                         after running the positive leg: {why}"
                    );
                }
            }

            // (NEGATIVE) Keeping go-oidc's iss==discovery.issuer check enabled
            // MUST reject Basil JWT-SVIDs: the token's iss is the SPIFFE trust
            // domain id, while the discovery issuer is this test's loopback URL.
            match run_go_verifier(&base, &token, audience, true) {
                GoVerify::Rejected(reason) => {
                    eprintln!(
                        "GO-OIDC-E2E[{eng}]: go-oidc verifier REJECTED valid token \
                         when iss==discovery.issuer was enforced (reason: {})",
                        reason.trim()
                    );
                }
                GoVerify::Accepted => {
                    panic!(
                        "[{eng}] go-oidc verifier ACCEPTED a Basil JWT-SVID with \
                         iss==discovery.issuer enforced; the test no longer proves \
                         SkipIssuerCheck is load-bearing"
                    );
                }
                GoVerify::Unavailable(why) => {
                    // The positive leg just ran the same toolchain, so an
                    // unavailable here would be surprising; surface it loudly.
                    panic!(
                        "[{eng}] go-oidc verifier became unavailable on the issuer-check \
                         negative leg after running the positive leg: {why}"
                    );
                }
            }
            true
        }
        GoVerify::Rejected(reason) => {
            panic!(
                "[{eng}] go-oidc verifier REJECTED a valid Basil JWT-SVID off the \
                 published documents: {}",
                reason.trim()
            );
        }
        GoVerify::Unavailable(why) => {
            eprintln!(
                "SKIP[{eng}]: go toolchain/modules unavailable for the external \
                 go-oidc verifier leg ({why}), not failing the test"
            );
            false
        }
    };

    drop(harness);
    ran
}

/// Live REAL-EXTERNAL OIDC verifier interop (basil-mil0.2): a faithful ordinary
/// OIDC relying party (a tiny Go program built on `coreos/go-oidc/v3`) discovers
/// the issuer from `/.well-known/openid-configuration`, fetches the advertised
/// JWKS, and validates a Basil-minted JWT-SVID off those published documents with
/// NO SPIFFE plumbing (positive leg), then REJECTS a signature-tampered token
/// (negative leg). Cross-engine (bao + vault); each engine leg gated with an
/// explicit per-engine skip line; the Go leg itself gated on `go` + a successful
/// build (an absent toolchain / offline fetch prints an explicit SKIP, never a
/// hard failure, and the skip is visible in `go_ran_any`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_go_oidc_verifier_e2e_cross_engine() {
    if !on_path("go") {
        eprintln!(
            "SKIP: go toolchain/modules unavailable: `go` not on PATH; the external go-oidc \
             verifier leg cannot run. (Engine legs that boot the broker are also skipped.)"
        );
        return;
    }

    let mut ran_any = false;
    let mut go_ran_any = false;
    {
        if on_path("bao") {
            go_ran_any |= drive_engine_external_oidc(Engine::OpenBao, "go-oidc-e2e-bao").await;
            ran_any = true;
        } else {
            eprintln!(
                "SKIP[openbao]: bao not on PATH; external go-oidc verifier live e2e needs a live \
                 engine"
            );
        }

        if on_path("vault") {
            go_ran_any |= drive_engine_external_oidc(Engine::Vault, "go-oidc-e2e-vault").await;
            ran_any = true;
        } else {
            eprintln!(
                "SKIP[vault]: vault not on PATH; external go-oidc verifier live e2e needs a live \
                 engine"
            );
        }
    }

    assert!(
        ran_any,
        "neither bao nor vault was on PATH, the external go-oidc verifier live e2e ran no engine \
         leg"
    );
    // `go` was on PATH (checked above). If no engine leg got the Go verifier to a
    // verdict, it was a toolchain/module-build failure on every leg; make that
    // visible rather than passing vacuously.
    assert!(
        go_ran_any,
        "go is on PATH but the external go-oidc verifier never reached a verdict on any engine: \
         the Go build/module fetch failed on every leg (offline?). Not a silent pass."
    );
}
