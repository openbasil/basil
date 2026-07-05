package coseinterop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	cose "github.com/veraison/go-cose"
)

type es256Fixture struct {
	Key struct {
		KeyID         string `json:"key_id"`
		PublicSec1    string `json:"public_sec1_hex"`
		PrivateScalar string `json:"private_scalar_hex"`
	} `json:"key"`
	ContentType  string `json:"content_type"`
	PayloadHex   string `json:"payload_hex"`
	CoseSign1Hex string `json:"cose_sign1_hex"`
}

func loadEs256Fixture(t *testing.T) es256Fixture {
	t.Helper()
	path := filepath.Clean(filepath.Join("..", "..", "..", "basil-proto", "fixtures", "cose-es256-sign1-v1.json"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ES256 fixture: %v", err)
	}
	var fixture es256Fixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse ES256 fixture: %v", err)
	}
	return fixture
}

// es256PublicKey rebuilds a P-256 public key from uncompressed SEC1 bytes
// (0x04 || X || Y) without any deprecated elliptic helpers.
func es256PublicKey(t *testing.T, sec1 []byte) *ecdsa.PublicKey {
	t.Helper()
	if len(sec1) != 65 || sec1[0] != 0x04 {
		t.Fatalf("expected 65-byte uncompressed SEC1 point, got %d bytes", len(sec1))
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(sec1[1:33]),
		Y:     new(big.Int).SetBytes(sec1[33:65]),
	}
}

// TestGoCoseVerifiesBasilEs256Sign1 proves that Basil's deterministic ES256
// COSE_Sign1 is verifiable by veraison/go-cose and re-encodes byte-identically.
func TestGoCoseVerifiesBasilEs256Sign1(t *testing.T) {
	fixture := loadEs256Fixture(t)
	taggedHex := fixture.CoseSign1Hex
	sec1, err := hex.DecodeString(fixture.Key.PublicSec1)
	if err != nil {
		t.Fatalf("decode public sec1: %v", err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, es256PublicKey(t, sec1))
	if err != nil {
		t.Fatalf("new ES256 verifier: %v", err)
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(unhexBare(t, taggedHex)); err != nil {
		t.Fatalf("decode ES256 Sign1: %v", err)
	}
	if got, err := msg.MarshalCBOR(); err != nil {
		t.Fatalf("re-encode ES256 Sign1: %v", err)
	} else if hex.EncodeToString(got) != taggedHex {
		t.Fatalf("go-cose re-encode changed ES256 fixture bytes")
	}
	if err := msg.Verify(nil, verifier); err != nil {
		t.Fatalf("go-cose verify ES256 Sign1: %v", err)
	}
}

// TestGoCoseRejectsTamperedBasilEs256Sign1 flips the last signature byte and
// confirms go-cose rejects it.
func TestGoCoseRejectsTamperedBasilEs256Sign1(t *testing.T) {
	fixture := loadEs256Fixture(t)
	bytes := unhexBare(t, fixture.CoseSign1Hex)
	bytes[len(bytes)-1] ^= 0x01
	sec1, err := hex.DecodeString(fixture.Key.PublicSec1)
	if err != nil {
		t.Fatalf("decode public sec1: %v", err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, es256PublicKey(t, sec1))
	if err != nil {
		t.Fatalf("new ES256 verifier: %v", err)
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(bytes); err != nil {
		return // a decode failure is also a rejection
	}
	if err := msg.Verify(nil, verifier); err == nil {
		t.Fatalf("go-cose accepted tampered ES256 Sign1")
	}
}

func unhexBare(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return out
}
