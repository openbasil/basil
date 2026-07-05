package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
)

type probeResult struct {
	Endpoint                 string `json:"endpoint"`
	TrustDomain              string `json:"trust_domain"`
	X509ContextOK            bool   `json:"x509_context_ok"`
	X509ContextSVIDs         int    `json:"x509_context_svids"`
	X509ContextBundles       int    `json:"x509_context_bundles"`
	X509SVIDID               string `json:"x509_svid_id"`
	X509SVIDChainLen         int    `json:"x509_svid_chain_len"`
	X509SVIDHasPrivateKey    bool   `json:"x509_svid_has_private_key"`
	X509Bundles              int    `json:"x509_bundles"`
	JWTSVIDID                string `json:"jwt_svid_id"`
	JWTSVIDAudienceOK        bool   `json:"jwt_svid_audience_ok"`
	JWTSVIDTokenNonEmpty     bool   `json:"jwt_svid_token_non_empty"`
	JWTBundles               int    `json:"jwt_bundles"`
	ValidateJWTSVIDOK        bool   `json:"validate_jwt_svid_ok"`
	ValidateJWTSVIDID        string `json:"validate_jwt_svid_id"`
	StandardClientHeaderPath bool   `json:"standard_client_header_path"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "go-spiffe probe failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	endpoint := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if endpoint == "" {
		return fmt.Errorf("SPIFFE_ENDPOINT_SOCKET is required")
	}
	trustDomain := envDefault("BASIL_SPIFFE_TRUST_DOMAIN", "example.org")
	audience := envDefault("BASIL_SPIFFE_AUDIENCE", "basil-go-spiffe-probe")
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return fmt.Errorf("parse trust domain %q: %w", trustDomain, err)
	}
	if len(os.Args) > 1 && os.Args[1] == "examples" {
		result, err := runExampleProbes(context.Background(), endpoint, td)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := workloadapi.New(
		ctx,
		workloadapi.WithAddr(goSpiffeEndpoint(endpoint)),
		workloadapi.WithDialOptions(grpc.WithAuthority("localhost")),
	)
	if err != nil {
		return fmt.Errorf("connect workload api: %w", err)
	}
	defer client.Close()

	x509Ctx, err := client.FetchX509Context(ctx)
	if err != nil {
		return fmt.Errorf("FetchX509Context: %w", err)
	}
	if len(x509Ctx.SVIDs) == 0 {
		return fmt.Errorf("FetchX509Context returned no SVIDs")
	}
	defaultSVID := x509Ctx.DefaultSVID()
	if defaultSVID.ID.TrustDomain() != td {
		return fmt.Errorf("default X509-SVID trust domain %s, want %s", defaultSVID.ID.TrustDomain(), td)
	}

	x509SVID, err := client.FetchX509SVID(ctx)
	if err != nil {
		return fmt.Errorf("FetchX509SVID: %w", err)
	}
	if x509SVID.ID.TrustDomain() != td {
		return fmt.Errorf("X509-SVID trust domain %s, want %s", x509SVID.ID.TrustDomain(), td)
	}

	x509Bundles, err := client.FetchX509Bundles(ctx)
	if err != nil {
		return fmt.Errorf("FetchX509Bundles: %w", err)
	}
	if bundle, err := x509Bundles.GetX509BundleForTrustDomain(td); err != nil {
		return fmt.Errorf("x509 bundle for %s: %w", td, err)
	} else if len(bundle.X509Authorities()) == 0 {
		return fmt.Errorf("x509 bundle for %s has no authorities", td)
	}

	jwtSVID, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
	if err != nil {
		return fmt.Errorf("FetchJWTSVID: %w", err)
	}
	if jwtSVID.ID.TrustDomain() != td {
		return fmt.Errorf("JWT-SVID trust domain %s, want %s", jwtSVID.ID.TrustDomain(), td)
	}
	if jwtSVID.Marshal() == "" {
		return fmt.Errorf("JWT-SVID token is empty")
	}

	jwtBundles, err := client.FetchJWTBundles(ctx)
	if err != nil {
		return fmt.Errorf("FetchJWTBundles: %w", err)
	}
	if bundle, err := jwtBundles.GetJWTBundleForTrustDomain(td); err != nil {
		return fmt.Errorf("jwt bundle for %s: %w", td, err)
	} else if len(bundle.JWTAuthorities()) == 0 {
		return fmt.Errorf("jwt bundle for %s has no authorities", td)
	}

	validated, err := client.ValidateJWTSVID(ctx, jwtSVID.Marshal(), audience)
	if err != nil {
		return fmt.Errorf("ValidateJWTSVID: %w", err)
	}
	if validated.ID != jwtSVID.ID {
		return fmt.Errorf("validated JWT-SVID id %s, want %s", validated.ID, jwtSVID.ID)
	}

	result := probeResult{
		Endpoint:                 endpoint,
		TrustDomain:              trustDomain,
		X509ContextOK:            true,
		X509ContextSVIDs:         len(x509Ctx.SVIDs),
		X509ContextBundles:       x509Ctx.Bundles.Len(),
		X509SVIDID:               x509SVID.ID.String(),
		X509SVIDChainLen:         len(x509SVID.Certificates),
		X509SVIDHasPrivateKey:    x509SVID.PrivateKey != nil,
		X509Bundles:              x509Bundles.Len(),
		JWTSVIDID:                jwtSVID.ID.String(),
		JWTSVIDAudienceOK:        contains(jwtSVID.Audience, audience),
		JWTSVIDTokenNonEmpty:     jwtSVID.Marshal() != "",
		JWTBundles:               jwtBundles.Len(),
		ValidateJWTSVIDOK:        true,
		ValidateJWTSVIDID:        validated.ID.String(),
		StandardClientHeaderPath: true,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func goSpiffeEndpoint(endpoint string) string {
	if strings.HasPrefix(endpoint, "unix://") || strings.HasPrefix(endpoint, "tcp://") {
		return endpoint
	}
	if strings.HasPrefix(endpoint, "unix:") {
		return "unix://" + strings.TrimPrefix(endpoint, "unix:")
	}
	return endpoint
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
