// Command es256produce signs a bare COSE_Sign1 under ES256 with go-cose,
// using the P-256 key material from the checked-in Basil ES256 fixture, and
// prints the tagged bytes as hex. Basil's P256Verifier must accept the result,
// proving Basil verifies standard (reference-produced) ES256 signatures.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // register SHA-256 for go-cose ES256 signing
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	cose "github.com/veraison/go-cose"
)

type es256Fixture struct {
	Key struct {
		KeyID         string `json:"key_id"`
		PublicSec1    string `json:"public_sec1_hex"`
		PrivateScalar string `json:"private_scalar_hex"`
	} `json:"key"`
}

func mustUnhex(value string) []byte {
	out, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return out
}

func main() {
	path := filepath.Clean(filepath.Join("..", "..", "..", "basil-proto", "fixtures", "cose-es256-sign1-v1.json"))
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var fixture es256Fixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		panic(err)
	}

	sec1 := mustUnhex(fixture.Key.PublicSec1)
	if len(sec1) != 65 || sec1[0] != 0x04 {
		panic("expected 65-byte uncompressed SEC1 public key")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = new(big.Int).SetBytes(mustUnhex(fixture.Key.PrivateScalar))
	priv.X = new(big.Int).SetBytes(sec1[1:33])
	priv.Y = new(big.Int).SetBytes(sec1[33:65])

	signer, err := cose.NewSigner(cose.AlgorithmES256, priv)
	if err != nil {
		panic(err)
	}
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
			cose.HeaderLabelCritical:    []any{cose.HeaderLabelContentType},
			cose.HeaderLabelContentType: "application/basil.go-es256-interop",
			cose.HeaderLabelKeyID:       []byte(fixture.Key.KeyID),
		},
		Unprotected: cose.UnprotectedHeader{},
	}
	msg, err := cose.Sign1(rand.Reader, signer, headers, []byte("go-cose es256 payload"), nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(msg))
}
