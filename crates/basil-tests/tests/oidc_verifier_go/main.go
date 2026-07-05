// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

// Command oidcverifier is a tiny, faithful "ordinary OIDC relying party" used as
// an EXTERNAL verifier in Basil's live e2e (br basil-mil0.2). It proves a Basil
// JWT-SVID validates off nothing but Basil's PUBLISHED OIDC documents: the
// OpenID-Connect discovery doc (/.well-known/openid-configuration) and the JWKS
// it advertises, with NO SPIFFE plumbing whatsoever.
//
// It uses github.com/coreos/go-oidc/v3, the standard Go OIDC client:
//
//   - oidc.NewProvider(ctx, issuer) consumes the issuer's
//     /.well-known/openid-configuration (this is the OP-metadata discovery step)
//     and learns the jwks_uri;
//   - provider.Verifier(...) fetches the JWKS from that jwks_uri, selects the key
//     by the token's `kid`, and validates the RS256 signature.
//
// Basil-specific verifier configuration (see the e2e and operations runbook):
//
//   - SkipIssuerCheck: a Basil JWT-SVID's `iss` is the SPIFFE trust-domain id
//     (e.g. spiffe://example.org), which is DIFFERENT from the OIDC discovery
//     `issuer` (a configured http(s) URL). An ordinary OIDC verifier MUST skip
//     the iss==discovery.issuer check or every Basil token fail-closes.
//   - SkipClientIDCheck + an explicit expected-audience compare: go-oidc's
//     ClientID-based aud check assumes the RP's own client id; we instead skip it
//     and assert the audience ourselves so the test controls the expected aud.
//   - SupportedSigningAlgs: []string{"RS256"}, Basil JWT-SVIDs are RS256.
//   - oidc.InsecureIssuerURLContext: the e2e issuer is an http://127.0.0.1:<port>
//     loopback URL. go-oidc's NewProvider otherwise requires the metadata
//     `issuer` to match the request URL; this context lets a localhost http issuer
//     through. It does NOT relax signature verification, only the discovery
//     issuer-string match for NewProvider.
//
// Usage (the first three may also be supplied via env: OIDC_ISSUER, OIDC_TOKEN,
// OIDC_AUDIENCE: env wins over args so the harness can pass the token off-cmdline).
// Set OIDC_ENFORCE_ISS=1 to keep go-oidc's iss==discovery.issuer check enabled;
// Basil JWT-SVIDs should fail in that mode because their iss is a SPIFFE ID.
//
//	oidcverifier <issuer-url> <token> <expected-audience>
//
// Exit code: 0 if the token validates (signature + kid resolved off the published
// JWKS, audience matches); nonzero with a one-line stderr reason otherwise.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func arg(i int, env string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	if i < len(os.Args) {
		return os.Args[i]
	}
	return ""
}

func run() error {
	issuer := arg(1, "OIDC_ISSUER")
	token := arg(2, "OIDC_TOKEN")
	audience := arg(3, "OIDC_AUDIENCE")
	enforceIssuer := os.Getenv("OIDC_ENFORCE_ISS") == "1"
	if issuer == "" || token == "" || audience == "" {
		return errors.New("usage: oidcverifier <issuer-url> <token> <expected-audience> (or OIDC_ISSUER/OIDC_TOKEN/OIDC_AUDIENCE)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Let a loopback http://127.0.0.1:<port> issuer through NewProvider's
	// metadata-issuer-match. This relaxes ONLY the discovery issuer-string match,
	// never the cryptographic verification.
	ctx = oidc.InsecureIssuerURLContext(ctx, issuer)

	// Discovery: consume /.well-known/openid-configuration from the issuer and
	// learn its jwks_uri. This is the real OP-metadata discovery step.
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return fmt.Errorf("discovery (NewProvider on %s/.well-known/openid-configuration): %w", issuer, err)
	}

	// Build a verifier off the discovered keys. By default we skip the OIDC iss
	// check (Basil's iss is the SPIFFE td, not the discovery issuer); the e2e can
	// flip OIDC_ENFORCE_ISS=1 to prove that check is load-bearing. We always skip
	// the built-in ClientID audience check (we assert the audience ourselves below)
	// and enforce the RS256 signature against the discovered JWKS, selected by the
	// token's kid.
	verifier := provider.Verifier(&oidc.Config{
		SkipClientIDCheck:    true,
		SkipIssuerCheck:      !enforceIssuer,
		SupportedSigningAlgs: []string{"RS256"},
	})

	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return fmt.Errorf("verify (signature/kid off the discovered JWKS): %w", err)
	}

	// Audience: go-oidc parses aud into IDToken.Audience; we assert the expected
	// audience explicitly (SkipClientIDCheck disabled the built-in check).
	matched := false
	for _, a := range idToken.Audience {
		if a == audience {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("audience mismatch: token aud=%v does not contain expected %q", idToken.Audience, audience)
	}

	fmt.Printf("OK: token validated off discovered JWKS (iss=%s aud=%v subject=%s)\n",
		idToken.Issuer, idToken.Audience, idToken.Subject)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "verify failed:", err)
		os.Exit(1)
	}
}
