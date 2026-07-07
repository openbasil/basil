// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Generated Basil gRPC API contracts.
//!
//! `broker` is Basil's own broker API. `spiffe` is generated from the vendored
//! upstream SPIFFE Workload API proto.

pub mod broker {
    pub mod v1 {
        #![allow(clippy::all, clippy::nursery, clippy::pedantic)]
        tonic::include_proto!("basil.broker.v1");
    }
}

pub mod google {
    pub mod rpc {
        #![allow(clippy::all, clippy::nursery, clippy::pedantic)]
        tonic::include_proto!("google.rpc");
    }
}

pub mod invocation;
pub mod types;
pub use types::{
    AeadAlgorithm, CatalogEntry, CatalogKind, CiphertextEnvelope, KeyMaterial, KeyType,
};
pub mod spiffe {
    #![allow(clippy::all, clippy::nursery, clippy::pedantic)]
    include!(concat!(env!("OUT_DIR"), "/_.rs"));
}
pub mod envoy {
    //! Minimal Envoy xDS/SDS v3 contracts used by Basil's SDS adapter.

    pub mod config {
        pub mod core {
            pub mod v3 {
                #![allow(clippy::all, clippy::nursery, clippy::pedantic)]
                tonic::include_proto!("envoy.config.core.v3");
            }
        }
        pub mod endpoint {
            pub mod v3 {
                #![allow(clippy::all, clippy::nursery, clippy::pedantic)]
                tonic::include_proto!("envoy.config.endpoint.v3");
            }
        }
        pub mod route {
            pub mod v3 {
                #![allow(clippy::all, clippy::nursery, clippy::pedantic)]
                tonic::include_proto!("envoy.config.route.v3");
            }
        }
    }

    pub mod extensions {
        pub mod transport_sockets {
            pub mod tls {
                pub mod v3 {
                    #![allow(clippy::all, clippy::nursery, clippy::pedantic)]
                    tonic::include_proto!("envoy.extensions.transport_sockets.tls.v3");
                }
            }
        }
    }

    pub mod service {
        pub mod discovery {
            pub mod v3 {
                #![allow(clippy::all, clippy::nursery, clippy::pedantic)]
                tonic::include_proto!("envoy.service.discovery.v3");
            }
        }
        pub mod secret {
            pub mod v3 {
                #![allow(clippy::all, clippy::nursery, clippy::pedantic)]
                tonic::include_proto!("envoy.service.secret.v3");
            }
        }
    }
}
pub mod xds {
    pub mod core {
        pub mod v3 {
            #![allow(clippy::all, clippy::nursery, clippy::pedantic)]
            tonic::include_proto!("xds.core.v3");
        }
    }
}

// Zeroize-on-drop for the secret-bearing wire messages. The broker moves
// secret/private-key bytes into these protos to send them, and the tonic codec
// drops the message right after encoding it. These impls wipe that last owned
// copy instead of leaving cleartext in freed heap (core security review
// findings 17/19). The codec's transient encode buffer is tonic-owned and out
// of reach. Note a `Drop` impl forbids moving fields out: consumers take owned
// bytes with `std::mem::take` on the field.

impl Drop for broker::v1::GetSecretResponse {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.value);
    }
}

impl Drop for broker::v1::IssueCertificateResponse {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.private_key_der);
    }
}

impl Drop for spiffe::X509svid {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.x509_svid_key);
    }
}

impl Drop for envoy::extensions::transport_sockets::tls::v3::TlsCertificate {
    fn drop(&mut self) {
        use envoy::config::core::v3::data_source::Specifier;
        if let Some(source) = self.private_key.as_mut()
            && let Some(specifier) = source.specifier.as_mut()
        {
            match specifier {
                Specifier::InlineBytes(bytes) => zeroize::Zeroize::zeroize(bytes),
                Specifier::Filename(text)
                | Specifier::InlineString(text)
                | Specifier::EnvironmentVariable(text) => zeroize::Zeroize::zeroize(text),
            }
        }
    }
}
