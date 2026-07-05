// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
)

type exampleProbeResult struct {
	X509SourceInitialUpdate     bool   `json:"x509_source_initial_update"`
	X509SourceRotationUpdate    bool   `json:"x509_source_rotation_update"`
	X509SourceRotatedLeaf       bool   `json:"x509_source_rotated_leaf"`
	X509SourceSVIDID            string `json:"x509_source_svid_id"`
	JWTSourceInitialUpdate      bool   `json:"jwt_source_initial_update"`
	MTLSSuccess                 bool   `json:"mtls_success"`
	MTLSRejectedWrongServerID   bool   `json:"mtls_rejected_wrong_server_id"`
	MTLSRejectedWrongClientID   bool   `json:"mtls_rejected_wrong_client_id"`
	MTLSPeerID                  string `json:"mtls_peer_id"`
	JWTHTTPSuccess              bool   `json:"jwt_http_success"`
	JWTWrongAudienceRejected    bool   `json:"jwt_wrong_audience_rejected"`
	JWTValidatedSubject         string `json:"jwt_validated_subject"`
	ConfigurableSocketAndIDs    bool   `json:"configurable_socket_and_ids"`
	UsedStandardExampleSurfaces bool   `json:"used_standard_example_surfaces"`
}

func runExampleProbes(parent context.Context, endpoint string, td spiffeid.TrustDomain) (*exampleProbeResult, error) {
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()

	sourceOpt := workloadapi.WithClientOptions(
		workloadapi.WithAddr(goSpiffeEndpoint(endpoint)),
		workloadapi.WithDialOptions(grpc.WithAuthority("localhost")),
	)

	x509Source, err := workloadapi.NewX509Source(ctx, sourceOpt)
	if err != nil {
		return nil, fmt.Errorf("create X509Source: %w", err)
	}
	defer x509Source.Close()
	x509SVID, err := x509Source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("get X509Source SVID: %w", err)
	}
	if x509SVID.ID.TrustDomain() != td {
		return nil, fmt.Errorf("X509Source SVID trust domain %s, want %s", x509SVID.ID.TrustDomain(), td)
	}
	if len(x509SVID.Certificates) == 0 {
		return nil, fmt.Errorf("X509Source SVID has no certificates")
	}
	initialLeaf := append([]byte(nil), x509SVID.Certificates[0].Raw...)

	jwtSource, err := workloadapi.NewJWTSource(ctx, sourceOpt)
	if err != nil {
		return nil, fmt.Errorf("create JWTSource: %w", err)
	}
	defer jwtSource.Close()
	if _, err := jwtSource.GetJWTBundleForTrustDomain(td); err != nil {
		return nil, fmt.Errorf("get JWTSource initial bundle: %w", err)
	}

	rotatedLeaf, err := waitForX509Rotation(ctx, x509Source, initialLeaf)
	if err != nil {
		return nil, err
	}

	mtls, err := runMTLSProbe(ctx, x509Source, x509SVID.ID)
	if err != nil {
		return nil, err
	}

	jwt, err := runJWTHTTPProbe(ctx, x509Source, jwtSource, x509SVID.ID)
	if err != nil {
		return nil, err
	}

	return &exampleProbeResult{
		X509SourceInitialUpdate:     true,
		X509SourceRotationUpdate:    true,
		X509SourceRotatedLeaf:       rotatedLeaf,
		X509SourceSVIDID:            x509SVID.ID.String(),
		JWTSourceInitialUpdate:      true,
		MTLSSuccess:                 mtls.success,
		MTLSRejectedWrongServerID:   mtls.rejectedWrongServerID,
		MTLSRejectedWrongClientID:   mtls.rejectedWrongClientID,
		MTLSPeerID:                  mtls.peerID,
		JWTHTTPSuccess:              jwt.success,
		JWTWrongAudienceRejected:    jwt.wrongAudienceRejected,
		JWTValidatedSubject:         jwt.subject,
		ConfigurableSocketAndIDs:    endpoint != "" && x509SVID.ID.String() != "",
		UsedStandardExampleSurfaces: true,
	}, nil
}

func waitForX509Rotation(ctx context.Context, source *workloadapi.X509Source, initialLeaf []byte) (bool, error) {
	readyFile := os.Getenv("BASIL_SPIFFE_ROTATION_READY_FILE")
	drainUpdates(source.Updated())
	if readyFile != "" {
		if err := os.WriteFile(readyFile, []byte("ready\n"), 0o600); err != nil {
			return false, fmt.Errorf("write rotation ready file: %w", err)
		}
	}
	select {
	case <-source.Updated():
	case <-ctx.Done():
		return false, fmt.Errorf("wait for X509Source rotation update: %w", ctx.Err())
	}
	rotated, err := source.GetX509SVID()
	if err != nil {
		return false, fmt.Errorf("get rotated X509Source SVID: %w", err)
	}
	if len(rotated.Certificates) == 0 {
		return false, fmt.Errorf("rotated X509Source SVID has no certificates")
	}
	return !sameBytes(initialLeaf, rotated.Certificates[0].Raw), nil
}

func sameBytes(left []byte, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i, value := range left {
		if value != right[i] {
			return false
		}
	}
	return true
}

func drainUpdates(ch <-chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

type mtlsProbe struct {
	success               bool
	rejectedWrongServerID bool
	rejectedWrongClientID bool
	peerID                string
}

func runMTLSProbe(ctx context.Context, source *workloadapi.X509Source, expectedID spiffeid.ID) (*mtlsProbe, error) {
	okServer, err := startMTLSServer(source, tlsconfig.AuthorizeID(expectedID))
	if err != nil {
		return nil, err
	}
	defer okServer.close(ctx)

	body, err := mtlsGet(ctx, source, expectedID, okServer.url)
	if err != nil {
		return nil, fmt.Errorf("mTLS client/server success path: %w", err)
	}
	var okPayload struct {
		PeerID string `json:"peer_id"`
	}
	if err := json.Unmarshal(body, &okPayload); err != nil {
		return nil, fmt.Errorf("decode mTLS success body: %w", err)
	}
	if okPayload.PeerID != expectedID.String() {
		return nil, fmt.Errorf("mTLS peer id %s, want %s", okPayload.PeerID, expectedID)
	}

	wrongID := spiffeid.RequireFromString(envDefault("BASIL_SPIFFE_WRONG_ID", "spiffe://example.org/not-the-peer"))
	_, wrongServerErr := mtlsGet(ctx, source, wrongID, okServer.url)

	denyServer, err := startMTLSServer(source, tlsconfig.AuthorizeID(wrongID))
	if err != nil {
		return nil, err
	}
	defer denyServer.close(ctx)
	_, wrongClientErr := mtlsGet(ctx, source, expectedID, denyServer.url)

	return &mtlsProbe{
		success:               true,
		rejectedWrongServerID: wrongServerErr != nil,
		rejectedWrongClientID: wrongClientErr != nil,
		peerID:                okPayload.PeerID,
	}, nil
}

type mtlsServer struct {
	url    string
	server *http.Server
}

func startMTLSServer(source *workloadapi.X509Source, authorizer tlsconfig.Authorizer) (*mtlsServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for mTLS probe: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		peerID := ""
		if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 && len(req.TLS.PeerCertificates[0].URIs) > 0 {
			peerID = req.TLS.PeerCertificates[0].URIs[0].String()
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"peer_id": peerID})
	})

	server := &http.Server{
		Handler:           mux,
		TLSConfig:         tlsconfig.MTLSServerConfig(source, source, authorizer),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = server.Serve(tls.NewListener(listener, server.TLSConfig))
	}()
	return &mtlsServer{
		url:    "https://" + listener.Addr().String(),
		server: server,
	}, nil
}

func (s *mtlsServer) close(ctx context.Context) {
	shutdownCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_ = s.server.Shutdown(shutdownCtx)
}

func mtlsGet(ctx context.Context, source *workloadapi.X509Source, expectedPeer spiffeid.ID, url string) ([]byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(expectedPeer)),
		},
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mTLS HTTP status %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

type jwtHTTPProbe struct {
	success               bool
	wrongAudienceRejected bool
	subject               string
}

func runJWTHTTPProbe(ctx context.Context, x509Source *workloadapi.X509Source, jwtSource *workloadapi.JWTSource, serverID spiffeid.ID) (*jwtHTTPProbe, error) {
	audience := envDefault("BASIL_SPIFFE_JWT_SERVER_AUDIENCE", "basil-go-spiffe-jwt-server")
	server, err := startJWTHTTPServer(x509Source, jwtSource, serverID, audience)
	if err != nil {
		return nil, err
	}
	defer server.close(ctx)

	goodToken, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
	if err != nil {
		return nil, fmt.Errorf("fetch good JWT-SVID: %w", err)
	}
	body, err := jwtHTTPGet(ctx, x509Source, serverID, server.url, goodToken.Marshal())
	if err != nil {
		return nil, fmt.Errorf("JWT HTTP success path: %w", err)
	}
	var okPayload struct {
		Subject string `json:"subject"`
	}
	if err := json.Unmarshal(body, &okPayload); err != nil {
		return nil, fmt.Errorf("decode JWT HTTP success body: %w", err)
	}
	if okPayload.Subject != goodToken.ID.String() {
		return nil, fmt.Errorf("JWT HTTP subject %s, want %s", okPayload.Subject, goodToken.ID)
	}

	badToken, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience + "-wrong"})
	if err != nil {
		return nil, fmt.Errorf("fetch wrong-audience JWT-SVID: %w", err)
	}
	_, wrongAudienceErr := jwtHTTPGet(ctx, x509Source, serverID, server.url, badToken.Marshal())

	return &jwtHTTPProbe{
		success:               true,
		wrongAudienceRejected: wrongAudienceErr != nil,
		subject:               okPayload.Subject,
	}, nil
}

func startJWTHTTPServer(x509Source *workloadapi.X509Source, jwtSource *workloadapi.JWTSource, serverID spiffeid.ID, audience string) (*mtlsServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for JWT HTTP probe: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fields := strings.Fields(req.Header.Get("Authorization"))
		if len(fields) != 2 || fields[0] != "Bearer" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		svid, err := jwtsvid.ParseAndValidate(fields[1], jwtSource, []string{audience})
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"subject": svid.ID.String()})
	})

	server := &http.Server{
		Handler:           mux,
		TLSConfig:         tlsconfig.TLSServerConfig(x509Source),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = server.Serve(tls.NewListener(listener, server.TLSConfig))
	}()
	return &mtlsServer{
		url:    "https://" + listener.Addr().String(),
		server: server,
	}, nil
}

func jwtHTTPGet(ctx context.Context, x509Source *workloadapi.X509Source, serverID spiffeid.ID, url string, token string) ([]byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig.TLSClientConfig(x509Source, tlsconfig.AuthorizeID(serverID)),
		},
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWT HTTP status %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}
