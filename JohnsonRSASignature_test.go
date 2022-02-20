package redactionschemes

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestJohnsonRSASignature(t *testing.T) {
	priv_key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Could not generate private key!")
		return
	}
	var sig JohnsonRSASignature
	test(t, priv_key, &sig)
}
