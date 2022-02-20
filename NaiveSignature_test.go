package redactionschemes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestNaiveSignature(t *testing.T) {
	priv_key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("Could not generate private key!")
		return
	}

	var sig NaiveSignature
	test(t, priv_key, &sig)
}
