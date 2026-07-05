//! Shared Vault PKI HTTP operations (`HashiCorp` Vault or `OpenBao`).
//!
//! PKI issue endpoints are catalog paths such as `pki/issue/web`. Unlike transit
//! operations, the path is already mount-qualified and is resolved directly under
//! `/v1/`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::transit::read_body;
use super::{BackendError, X509Bundle, X509CertRequest, X509Svid};

/// HTTP client for Vault PKI issue endpoints.
pub struct PkiClient {
    http: reqwest::Client,
    /// Base address, e.g. `http://127.0.0.1:8200` (no trailing slash).
    addr: String,
}

impl PkiClient {
    pub(crate) fn new(http: reqwest::Client, addr: &str) -> Self {
        Self {
            http,
            addr: addr.trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{}", self.addr, path)
    }

    async fn get_text_optional(
        &self,
        token: &str,
        path: &str,
    ) -> Result<Option<String>, BackendError> {
        let resp = self
            .http
            .get(self.url(path))
            .header("X-Vault-Token", token)
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(BackendError::Backend(error_message(status, &text)));
        }
        if text.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(text))
    }

    /// Issue an X.509-SVID leaf from a Vault PKI role.
    pub(crate) async fn issue_x509_svid(
        &self,
        token: &str,
        path: &str,
        spiffe_id: &str,
        ttl_seconds: u64,
    ) -> Result<X509Svid, BackendError> {
        let resp = self
            .http
            .post(self.url(path))
            .header("X-Vault-Token", token)
            .json(&json!({
                "uri_sans": spiffe_id,
                "ttl": format!("{ttl_seconds}s"),
                "format": "pem",
                "private_key_format": "pkcs8",
            }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        let body = read_body(resp)
            .await?
            .ok_or_else(|| BackendError::Protocol("empty pki issue response".into()))?;
        parse_issue_response(&body)
    }

    /// Issue a DNS/IP-SAN X.509 leaf (a TLS cert) from a Vault PKI role.
    ///
    /// Same issue endpoint as [`Self::issue_x509_svid`], but binds
    /// `common_name`/`alt_names`/`ip_sans` instead of `uri_sans`. The response is
    /// normalized by the shared [`parse_issue_response`].
    pub(crate) async fn issue_x509_cert(
        &self,
        token: &str,
        path: &str,
        request: &X509CertRequest,
    ) -> Result<X509Svid, BackendError> {
        let resp = self
            .http
            .post(self.url(path))
            .header("X-Vault-Token", token)
            .json(&json!({
                "common_name": request.common_name,
                "alt_names": request.dns_sans.join(","),
                "ip_sans": request.ip_sans.join(","),
                "ttl": format!("{}s", request.ttl_seconds),
                "format": "pem",
                "private_key_format": "pkcs8",
            }))
            .send()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))?;
        let body = read_body(resp)
            .await?
            .ok_or_else(|| BackendError::Protocol("empty pki issue response".into()))?;
        parse_issue_response(&body)
    }

    /// Read a PKI mount's CA bundle and CRL from an issue endpoint path.
    pub(crate) async fn x509_bundle(
        &self,
        token: &str,
        issue_path: &str,
    ) -> Result<X509Bundle, BackendError> {
        let mount = pki_mount_from_issue_path(issue_path)?;
        // Use the RAW `{mount}/ca_chain` endpoint, which returns the CA chain as
        // concatenated PEM directly. The JSON-enveloped `{mount}/cert/ca_chain`
        // wraps the PEM under `data.ca_chain`, which the PEM parser below cannot
        // consume. (Same on OpenBao and HashiCorp Vault.)
        let ca_chain = self
            .get_text_optional(token, &format!("{mount}/ca_chain"))
            .await?
            .ok_or_else(|| BackendError::KeyNotFound(format!("{mount}/ca_chain")))?;
        let crl_der = self
            .get_text_optional(token, &format!("{mount}/crl/pem"))
            .await?
            .map(|crl| pem_or_base64_der(&crl))
            .transpose()?
            .unwrap_or_default();

        Ok(X509Bundle {
            bundle_der: pem_bundle_der(&ca_chain)?,
            crl_der,
        })
    }
}

fn error_message(status: reqwest::StatusCode, text: &str) -> String {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| {
            v.get("errors").and_then(Value::as_array).map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("; ")
            })
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("HTTP {status}"))
}

fn pki_mount_from_issue_path(path: &str) -> Result<&str, BackendError> {
    let Some((mount, role)) = path.split_once("/issue/") else {
        return Err(BackendError::Protocol(format!(
            "pki issue path `{path}` must contain /issue/"
        )));
    };
    if mount.is_empty() || role.is_empty() {
        return Err(BackendError::Protocol(format!(
            "pki issue path `{path}` has empty mount or role"
        )));
    }
    Ok(mount)
}

fn parse_issue_response(body: &Value) -> Result<X509Svid, BackendError> {
    let data = body
        .get("data")
        .ok_or_else(|| BackendError::Protocol("missing data in pki issue response".into()))?;
    let leaf = data
        .get("certificate")
        .and_then(Value::as_str)
        .ok_or_else(|| BackendError::Protocol("missing certificate in pki issue".into()))?;
    let private_key = data
        .get("private_key")
        .and_then(Value::as_str)
        .ok_or_else(|| BackendError::Protocol("missing private_key in pki issue".into()))?;

    let mut cert_chain_der = Vec::from([pem_or_base64_der(leaf)?]);
    if let Some(chain) = data.get("ca_chain").and_then(Value::as_array) {
        for cert in chain.iter().filter_map(Value::as_str) {
            cert_chain_der.push(pem_or_base64_der(cert)?);
        }
    }

    let bundle_der = data
        .get("issuing_ca")
        .and_then(Value::as_str)
        .map(pem_or_base64_der)
        .transpose()?
        .into_iter()
        .collect();

    Ok(X509Svid {
        cert_chain_der,
        leaf_private_key_der: Zeroizing::new(pem_or_base64_der(private_key)?),
        bundle_der,
    })
}

fn pem_or_base64_der(input: &str) -> Result<Vec<u8>, BackendError> {
    let trimmed = input.trim();
    if trimmed.starts_with("-----BEGIN ") {
        let mut blocks = pem_bundle_der(trimmed)?;
        if blocks.len() != 1 {
            return Err(BackendError::Protocol(
                "expected exactly one PEM block".into(),
            ));
        }
        return blocks
            .pop()
            .ok_or_else(|| BackendError::Protocol("expected exactly one PEM block".into()));
    }
    B64.decode(trimmed)
        .map_err(|e| BackendError::Protocol(format!("DER field is not base64: {e}")))
}

fn pem_bundle_der(input: &str) -> Result<Vec<Vec<u8>>, BackendError> {
    let trimmed = input.trim();
    if !trimmed.starts_with("-----BEGIN ") {
        return B64
            .decode(trimmed)
            .map(|der| vec![der])
            .map_err(|e| BackendError::Protocol(format!("DER field is not base64: {e}")));
    }

    let mut parser = PemBundleParser::default();
    for line in input.lines().map(str::trim) {
        parser.push_line(line)?;
    }
    parser.finish()
}

#[derive(Default)]
struct PemBundleParser {
    blocks: Vec<Vec<u8>>,
    body: String,
    in_block: bool,
}

impl PemBundleParser {
    fn push_line(&mut self, line: &str) -> Result<(), BackendError> {
        match pem_line(line) {
            PemLine::Begin => self.begin_block(),
            PemLine::End => self.end_block(),
            PemLine::Body => {
                self.push_body_line(line);
                Ok(())
            }
        }
    }

    fn begin_block(&mut self) -> Result<(), BackendError> {
        if std::mem::replace(&mut self.in_block, true) {
            return Err(BackendError::Protocol("nested PEM block".into()));
        }
        self.body.clear();
        Ok(())
    }

    fn end_block(&mut self) -> Result<(), BackendError> {
        if !self.in_block || self.body.is_empty() {
            return Err(BackendError::Protocol("malformed PEM block".into()));
        }
        self.blocks.push(
            B64.decode(&self.body)
                .map_err(|e| BackendError::Protocol(format!("PEM body is not base64: {e}")))?,
        );
        self.in_block = false;
        self.body.clear();
        Ok(())
    }

    fn push_body_line(&mut self, line: &str) {
        if self.in_block {
            self.body.push_str(line);
        }
    }

    fn finish(self) -> Result<Vec<Vec<u8>>, BackendError> {
        if self.in_block || self.blocks.is_empty() {
            return Err(BackendError::Protocol("malformed PEM block".into()));
        }
        Ok(self.blocks)
    }
}

enum PemLine {
    Begin,
    End,
    Body,
}

fn pem_line(line: &str) -> PemLine {
    if line.starts_with("-----BEGIN ") && line.ends_with("-----") {
        return PemLine::Begin;
    }
    if line.starts_with("-----END ") && line.ends_with("-----") {
        return PemLine::End;
    }
    PemLine::Body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> PkiClient {
        crate::ensure_crypto_provider();
        PkiClient::new(reqwest::Client::new(), "http://127.0.0.1:8200/")
    }

    #[test]
    fn pki_paths_are_absolute_catalog_paths() {
        let c = client();
        assert_eq!(
            c.url("pki/issue/web"),
            "http://127.0.0.1:8200/v1/pki/issue/web"
        );
        assert_eq!(
            c.url("pki-prod/issue/spiffe"),
            "http://127.0.0.1:8200/v1/pki-prod/issue/spiffe"
        );
    }

    #[test]
    fn pem_body_decodes_to_der() {
        let pem = "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n";
        assert_eq!(
            pem_or_base64_der(pem).expect("PEM decodes"),
            vec![1, 2, 3, 4]
        );
    }

    #[test]
    fn pem_bundle_decodes_multiple_blocks() {
        let pem = "\
-----BEGIN CERTIFICATE-----
AQI=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
AwQ=
-----END CERTIFICATE-----
";
        assert_eq!(
            pem_bundle_der(pem).expect("PEM bundle decodes"),
            vec![vec![1, 2], vec![3, 4]]
        );
    }

    #[test]
    fn pki_mount_is_derived_from_issue_path() {
        assert_eq!(
            pki_mount_from_issue_path("pki/issue/workload").expect("mount"),
            "pki"
        );
        assert_eq!(
            pki_mount_from_issue_path("pki-prod/issue/spiffe").expect("mount"),
            "pki-prod"
        );
        assert!(pki_mount_from_issue_path("pki/cert/ca").is_err());
    }

    #[test]
    fn issue_response_normalizes_leaf_key_chain_and_bundle() {
        let body = json!({
            "data": {
                "certificate": "AQI=",
                "ca_chain": ["AwQ=", "BQY="],
                "issuing_ca": "Bwg=",
                "private_key": "CQo="
            }
        });
        let svid = parse_issue_response(&body).expect("issue response parses");
        assert_eq!(
            svid.cert_chain_der,
            vec![vec![1, 2], vec![3, 4], vec![5, 6]]
        );
        assert_eq!(&*svid.leaf_private_key_der, &[9, 10]);
        assert_eq!(svid.bundle_der, vec![vec![7, 8]]);
    }
}
