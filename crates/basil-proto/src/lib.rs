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
