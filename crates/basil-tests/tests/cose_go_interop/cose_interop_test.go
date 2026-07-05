package coseinterop

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type fixtureDoc struct {
	Keys    map[string]fixtureKey `json:"keys"`
	Vectors []fixtureVector       `json:"vectors"`
	Rejects []fixtureReject       `json:"rejects"`
}

type fixtureKey struct {
	KeyID      string `json:"key_id"`
	PrivateHex string `json:"private_hex"`
	PublicHex  string `json:"public_hex"`
}

type fixtureVector struct {
	Name             string      `json:"name"`
	Signer           string      `json:"signer"`
	Recipient        string      `json:"recipient"`
	ContentAlgorithm int64       `json:"content_algorithm"`
	Body             fixtureBody `json:"body"`
	CoseSign1Hex     string      `json:"cose_sign1_hex"`
}

type fixtureReject struct {
	Name         string `json:"name"`
	Verifier     string `json:"verifier"`
	CoseSign1Hex string `json:"cose_sign1_hex"`
}

type fixtureBody struct {
	PlaintextCborHex string `json:"plaintext_cbor_hex"`
}

type coseEncrypt struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int64]any
	Ciphertext  []byte
	Recipients  []coseRecipient
}

type coseRecipient struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int64]any
	Ciphertext  []byte
}

func loadFixture(t *testing.T) fixtureDoc {
	t.Helper()
	path := filepath.Clean(filepath.Join("..", "..", "..", "basil-proto", "fixtures", "cose-sealed-invocation-v1.json"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc fixtureDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return doc
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return out
}

func verify(t *testing.T, doc fixtureDoc, signer, taggedHex string) error {
	t.Helper()
	key := doc.Keys[signer]
	public := ed25519.PublicKey(unhex(t, key.PublicHex))
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, public)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(unhex(t, taggedHex)); err != nil {
		return err
	}
	if got, err := msg.MarshalCBOR(); err != nil {
		return err
	} else if hex.EncodeToString(got) != taggedHex {
		t.Fatalf("go-cose re-encode changed fixture bytes")
	}
	return msg.Verify(nil, verifier)
}

func asBytes(t *testing.T, value any) []byte {
	t.Helper()
	bytes, ok := value.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", value)
	}
	return bytes
}

func asMap(t *testing.T, value any) map[any]any {
	t.Helper()
	m, ok := value.(map[any]any)
	if !ok {
		t.Fatalf("expected map, got %T", value)
	}
	return m
}

func intField(t *testing.T, m map[int64]any, label int64) int64 {
	t.Helper()
	value, ok := m[label]
	if !ok {
		t.Fatalf("missing label %d", label)
	}
	switch v := value.(type) {
	case int64:
		return v
	case uint64:
		return int64(v)
	default:
		t.Fatalf("label %d has unexpected type %T", label, value)
	}
	return 0
}

func protectedMap(t *testing.T, raw []byte) map[int64]any {
	t.Helper()
	var out map[int64]any
	if err := cbor.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode protected header: %v", err)
	}
	return out
}

func partyIdentity(t *testing.T, m map[int64]any, label int64) any {
	t.Helper()
	if value, ok := m[label]; ok {
		return asBytes(t, value)
	}
	return nil
}

func kdfContext(t *testing.T, alg int64, parties map[int64]any, recipientProtected []byte) []byte {
	t.Helper()
	context := []any{
		alg,
		[]any{partyIdentity(t, parties, -21), nil, nil},
		[]any{partyIdentity(t, parties, -24), nil, nil},
		[]any{uint64(256), recipientProtected},
	}
	out, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("canonical cbor mode: %v", err)
	}
	encoded, err := out.Marshal(context)
	if err != nil {
		t.Fatalf("encode kdf context: %v", err)
	}
	return encoded
}

func encStructure(t *testing.T, protected []byte) []byte {
	t.Helper()
	out, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("canonical cbor mode: %v", err)
	}
	encoded, err := out.Marshal([]any{"Encrypt", protected, []byte{}})
	if err != nil {
		t.Fatalf("encode Enc_structure: %v", err)
	}
	return encoded
}

func decryptVector(t *testing.T, doc fixtureDoc, vector fixtureVector) []byte {
	t.Helper()
	var sign1 cose.Sign1Message
	if err := sign1.UnmarshalCBOR(unhex(t, vector.CoseSign1Hex)); err != nil {
		t.Fatalf("%s: decode Sign1: %v", vector.Name, err)
	}
	var tag cbor.Tag
	if err := cbor.Unmarshal(sign1.Payload, &tag); err != nil {
		t.Fatalf("%s: decode encrypt tag: %v", vector.Name, err)
	}
	if tag.Number != 96 {
		t.Fatalf("%s: encrypt tag = %d, want 96", vector.Name, tag.Number)
	}
	rawEncrypt, err := cbor.Marshal(tag.Content)
	if err != nil {
		t.Fatalf("%s: re-marshal encrypt content: %v", vector.Name, err)
	}
	var enc coseEncrypt
	if err := cbor.Unmarshal(rawEncrypt, &enc); err != nil {
		t.Fatalf("%s: decode encrypt body: %v", vector.Name, err)
	}
	if len(enc.Recipients) != 1 {
		t.Fatalf("%s: recipient count = %d", vector.Name, len(enc.Recipients))
	}
	recipient := enc.Recipients[0]
	protected := protectedMap(t, enc.Protected)
	if got := intField(t, protected, 1); got != vector.ContentAlgorithm {
		t.Fatalf("%s: content alg = %d, want %d", vector.Name, got, vector.ContentAlgorithm)
	}
	recipientProtected := protectedMap(t, recipient.Protected)
	if got := intField(t, recipientProtected, 1); got != -25 {
		t.Fatalf("%s: recipient alg = %d, want -25", vector.Name, got)
	}
	ephemeralKey := asMap(t, recipient.Unprotected[-1])
	ephemeral := asBytes(t, ephemeralKey[int64(-2)])
	private, err := ecdh.X25519().NewPrivateKey(unhex(t, doc.Keys[vector.Recipient].PrivateHex))
	if err != nil {
		t.Fatalf("%s: recipient private key: %v", vector.Name, err)
	}
	public, err := ecdh.X25519().NewPublicKey(ephemeral)
	if err != nil {
		t.Fatalf("%s: ephemeral public key: %v", vector.Name, err)
	}
	shared, err := private.ECDH(public)
	if err != nil {
		t.Fatalf("%s: ECDH: %v", vector.Name, err)
	}
	reader := hkdf.New(sha256.New, shared, nil, kdfContext(t, vector.ContentAlgorithm, recipientProtected, recipient.Protected))
	cek := make([]byte, 32)
	if _, err := io.ReadFull(reader, cek); err != nil {
		t.Fatalf("%s: HKDF: %v", vector.Name, err)
	}
	var aead cipher.AEAD
	switch vector.ContentAlgorithm {
	case 3:
		block, err := aes.NewCipher(cek)
		if err != nil {
			t.Fatalf("%s: AES key: %v", vector.Name, err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("%s: GCM: %v", vector.Name, err)
		}
	case 24:
		aead, err = chacha20poly1305.New(cek)
		if err != nil {
			t.Fatalf("%s: chacha20poly1305: %v", vector.Name, err)
		}
	default:
		t.Fatalf("%s: unsupported content alg %d", vector.Name, vector.ContentAlgorithm)
	}
	nonce := asBytes(t, enc.Unprotected[5])
	plaintext, err := aead.Open(nil, nonce, enc.Ciphertext, encStructure(t, enc.Protected))
	if err != nil {
		t.Fatalf("%s: AEAD open: %v", vector.Name, err)
	}
	return plaintext
}

func TestGoCoseVerifiesBasilFixtureSignatures(t *testing.T) {
	doc := loadFixture(t)
	for _, vector := range doc.Vectors {
		if err := verify(t, doc, vector.Signer, vector.CoseSign1Hex); err != nil {
			t.Fatalf("%s: verify: %v", vector.Name, err)
		}
	}
}

func TestGoDecryptsBasilSealedFixtureBodies(t *testing.T) {
	doc := loadFixture(t)
	for _, vector := range doc.Vectors {
		plaintext := decryptVector(t, doc, vector)
		want := unhex(t, vector.Body.PlaintextCborHex)
		if !bytes.Equal(plaintext, want) {
			t.Fatalf("%s: plaintext mismatch", vector.Name)
		}
	}
}

func TestGoCoseRejectsBasilSignatureTamperVectors(t *testing.T) {
	doc := loadFixture(t)
	for _, reject := range doc.Rejects {
		switch reject.Name {
		case "tampered-signature", "wrong-outer-tag", "truncated":
			if err := verify(t, doc, reject.Verifier, reject.CoseSign1Hex); err == nil {
				t.Fatalf("%s: go-cose accepted tamper vector", reject.Name)
			} else if fmt.Sprint(err) == "" {
				t.Fatalf("%s: empty error", reject.Name)
			}
		}
	}
}
