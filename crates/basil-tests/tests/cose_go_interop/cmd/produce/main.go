package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	cose "github.com/veraison/go-cose"
)

type fixtureDoc struct {
	Keys map[string]fixtureKey `json:"keys"`
}

type fixtureKey struct {
	KeyID      string `json:"key_id"`
	PrivateHex string `json:"private_hex"`
}

func mustUnhex(value string) []byte {
	out, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return out
}

func main() {
	path := filepath.Clean(filepath.Join("..", "..", "..", "basil-proto", "fixtures", "cose-sealed-invocation-v1.json"))
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var doc fixtureDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		panic(err)
	}
	key := doc.Keys["client-signing"]
	private := ed25519.NewKeyFromSeed(mustUnhex(key.PrivateHex))
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, private)
	if err != nil {
		panic(err)
	}
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm:   cose.AlgorithmEdDSA,
			cose.HeaderLabelCritical:    []any{cose.HeaderLabelContentType},
			cose.HeaderLabelContentType: "application/basil.go-interop",
			cose.HeaderLabelKeyID:       []byte(key.KeyID),
		},
		Unprotected: cose.UnprotectedHeader{},
	}
	msg, err := cose.Sign1(rand.Reader, signer, headers, []byte("go-cose signed payload"), nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(msg))
}
