// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use basil_proto::broker::v1 as pb;
use basil_proto::broker::v1::nix_cache_service_client::NixCacheServiceClient;
use basil_proto::broker::v1::nix_cache_service_server::{NixCacheService, NixCacheServiceServer};
use prost::Message;
use prost::bytes::{Buf as _, BufMut as _};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codec::{BufferSettings, Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::codegen::http::uri::PathAndQuery;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Code, Request, Response, Status};

const ID: [u8; 16] = [1; 16];

#[derive(Clone, Default)]
struct CountingService {
    describe_calls: Arc<AtomicUsize>,
    enroll_calls: Arc<AtomicUsize>,
    sign_calls: Arc<AtomicUsize>,
    malformed_response: bool,
}

#[tonic::async_trait]
impl NixCacheService for CountingService {
    async fn describe_nix_cache_key(
        &self,
        request: Request<pb::DescribeNixCacheKeyRequest>,
    ) -> Result<Response<pb::DescribeNixCacheKeyResponse>, Status> {
        self.describe_calls.fetch_add(1, Ordering::Relaxed);
        let body = request.into_inner();
        Ok(Response::new(pb::DescribeNixCacheKeyResponse {
            key_name: if self.malformed_response {
                "k".repeat(129)
            } else {
                "cache.example-1".to_string()
            },
            public_key: vec![1; 32],
            backend_version: 1,
            batch_id: body.batch_id,
            request_id: body.request_id,
        }))
    }

    async fn enroll_nix_cache_key(
        &self,
        request: Request<pb::EnrollNixCacheKeyRequest>,
    ) -> Result<Response<pb::EnrollNixCacheKeyResponse>, Status> {
        self.enroll_calls.fetch_add(1, Ordering::Relaxed);
        let body = request.into_inner();
        Ok(Response::new(pb::EnrollNixCacheKeyResponse {
            key_name: "cache.example-1".to_string(),
            public_key: vec![1; 32],
            backend_version: 1,
            disposition: pb::NixCacheEnrollmentDisposition::Created.into(),
            batch_id: body.batch_id,
            request_id: body.request_id,
        }))
    }

    async fn sign_nix_cache_fingerprint(
        &self,
        request: Request<pb::SignNixCacheFingerprintRequest>,
    ) -> Result<Response<pb::SignNixCacheFingerprintResponse>, Status> {
        self.sign_calls.fetch_add(1, Ordering::Relaxed);
        let body = request.into_inner();
        Ok(Response::new(pb::SignNixCacheFingerprintResponse {
            key_name: "cache.example-1".to_string(),
            public_key: vec![1; 32],
            backend_version: 1,
            signature: vec![1; 64],
            batch_id: body.batch_id,
            request_id: body.request_id,
        }))
    }
}

#[derive(Debug, Clone)]
struct RawCodec<T, U>(PhantomData<(T, U)>);

impl<T, U> Default for RawCodec<T, U> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T, U> Codec for RawCodec<T, U>
where
    T: Send + 'static,
    U: Send + 'static,
{
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = RawEncoder;
    type Decoder = RawDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        RawEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        RawDecoder
    }
}

#[derive(Debug, Clone, Copy)]
struct RawEncoder;

impl Encoder for RawEncoder {
    type Item = Vec<u8>;
    type Error = Status;

    fn encode(
        &mut self,
        item: Self::Item,
        destination: &mut EncodeBuf<'_>,
    ) -> Result<(), Self::Error> {
        destination.put_slice(&item);
        Ok(())
    }

    fn buffer_settings(&self) -> BufferSettings {
        BufferSettings::default()
    }
}

#[derive(Debug, Clone, Copy)]
struct RawDecoder;

impl Decoder for RawDecoder {
    type Item = Vec<u8>;
    type Error = Status;

    fn decode(&mut self, source: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        Ok(Some(source.copy_to_bytes(source.remaining()).to_vec()))
    }

    fn buffer_settings(&self) -> BufferSettings {
        BufferSettings::default()
    }
}

async fn raw_unary(
    channel: Channel,
    path: &'static str,
    body: Vec<u8>,
) -> Result<Response<Vec<u8>>, Status> {
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready()
        .await
        .map_err(|error| Status::unknown(format!("service not ready: {error}")))?;
    grpc.unary(
        Request::new(body),
        PathAndQuery::from_static(path),
        RawCodec::<Vec<u8>, Vec<u8>>::default(),
    )
    .await
}

async fn assert_invalid(channel: &Channel, path: &'static str, body: Vec<u8>) {
    let status = raw_unary(channel.clone(), path, body).await.unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
}

async fn start_server(
    service: CountingService,
) -> (
    Channel,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(NixCacheServiceServer::new(service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    let channel = Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (channel, shutdown_tx, server)
}

#[tokio::test]
async fn malformed_requests_are_rejected_before_the_handler() {
    let service = CountingService::default();
    let describe_calls = Arc::clone(&service.describe_calls);
    let enroll_calls = Arc::clone(&service.enroll_calls);
    let sign_calls = Arc::clone(&service.sign_calls);
    let (channel, shutdown_tx, server) = start_server(service).await;

    let valid = pb::DescribeNixCacheKeyRequest {
        key_id: "cache-key".to_string(),
        batch_id: ID.to_vec(),
        request_id: ID.to_vec(),
    }
    .encode_to_vec();

    let mut unknown = valid.clone();
    unknown.extend_from_slice(&[0x20, 0x01]);
    assert_invalid(
        &channel,
        "/basil.broker.v1.NixCacheService/DescribeNixCacheKey",
        unknown,
    )
    .await;

    let valid_enroll = pb::EnrollNixCacheKeyRequest {
        key_id: "cache-key".to_string(),
        batch_id: ID.to_vec(),
        request_id: ID.to_vec(),
    }
    .encode_to_vec();
    let mut duplicate = valid_enroll;
    duplicate.extend_from_slice(&[0x0a, 0x01, b'x']);
    assert_invalid(
        &channel,
        "/basil.broker.v1.NixCacheService/EnrollNixCacheKey",
        duplicate,
    )
    .await;

    let missing = pb::EnrollNixCacheKeyRequest {
        key_id: "cache-key".to_string(),
        batch_id: ID.to_vec(),
        request_id: Vec::new(),
    }
    .encode_to_vec();
    assert_invalid(
        &channel,
        "/basil.broker.v1.NixCacheService/EnrollNixCacheKey",
        missing,
    )
    .await;

    assert_invalid(
        &channel,
        "/basil.broker.v1.NixCacheService/SignNixCacheFingerprint",
        vec![0x08, 0x01],
    )
    .await;

    let oversized = pb::DescribeNixCacheKeyRequest {
        key_id: "k".repeat(257),
        batch_id: ID.to_vec(),
        request_id: ID.to_vec(),
    }
    .encode_to_vec();
    assert_invalid(
        &channel,
        "/basil.broker.v1.NixCacheService/DescribeNixCacheKey",
        oversized,
    )
    .await;

    let oversized_sign = pb::SignNixCacheFingerprintRequest {
        key_id: "k".repeat(256),
        profile: "PATH_INFO_V1".to_string(),
        fingerprint: vec![b'x'; 524_627],
        batch_id: ID.to_vec(),
        request_id: ID.to_vec(),
    }
    .encode_to_vec();
    assert_invalid(
        &channel,
        "/basil.broker.v1.NixCacheService/SignNixCacheFingerprint",
        oversized_sign,
    )
    .await;
    assert_eq!(describe_calls.load(Ordering::Relaxed), 0);
    assert_eq!(enroll_calls.load(Ordering::Relaxed), 0);
    assert_eq!(sign_calls.load(Ordering::Relaxed), 0);

    let response = raw_unary(
        channel,
        "/basil.broker.v1.NixCacheService/DescribeNixCacheKey",
        valid,
    )
    .await
    .unwrap();
    let response =
        pb::DescribeNixCacheKeyResponse::decode(response.into_inner().as_slice()).unwrap();
    assert_eq!(response.key_name, "cache.example-1");
    assert_eq!(describe_calls.load(Ordering::Relaxed), 1);

    shutdown_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn generated_client_rejects_malformed_response_in_strict_codec() {
    let service = CountingService {
        malformed_response: true,
        ..CountingService::default()
    };
    let calls = Arc::clone(&service.describe_calls);
    let (channel, shutdown_tx, server) = start_server(service).await;
    let mut client = NixCacheServiceClient::new(channel);

    let status = client
        .describe_nix_cache_key(pb::DescribeNixCacheKeyRequest {
            key_id: "cache-key".to_string(),
            batch_id: ID.to_vec(),
            request_id: ID.to_vec(),
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::DataLoss);
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    shutdown_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
}
