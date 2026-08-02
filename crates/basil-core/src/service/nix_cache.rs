// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed Nix cache gRPC seam pending semantic implementation.

use basil_proto::broker::v1 as pb;
use basil_proto::broker::v1::nix_cache_service_server::NixCacheService;
use tonic::{Request, Response, Status};

use crate::grpc::BrokerGrpc;

#[tonic::async_trait]
impl NixCacheService for BrokerGrpc {
    async fn describe_nix_cache_key(
        &self,
        _request: Request<pb::DescribeNixCacheKeyRequest>,
    ) -> Result<Response<pb::DescribeNixCacheKeyResponse>, Status> {
        Err(Status::unimplemented(
            "Nix cache key description is not implemented",
        ))
    }

    async fn enroll_nix_cache_key(
        &self,
        _request: Request<pb::EnrollNixCacheKeyRequest>,
    ) -> Result<Response<pb::EnrollNixCacheKeyResponse>, Status> {
        Err(Status::unimplemented(
            "Nix cache key enrollment is not implemented",
        ))
    }

    async fn sign_nix_cache_fingerprint(
        &self,
        _request: Request<pb::SignNixCacheFingerprintRequest>,
    ) -> Result<Response<pb::SignNixCacheFingerprintResponse>, Status> {
        Err(Status::unimplemented(
            "Nix cache fingerprint signing is not implemented",
        ))
    }
}
