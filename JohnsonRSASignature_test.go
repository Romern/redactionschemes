package redactionschemes

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

func TestJohnsonRSASignature(t *testing.T) {
	priv_key, err := rsa.GenerateKey(rand.Reader, 2048)
	fmt.Println("Getting phi...")
	phi := GetEulerPhi(priv_key)
	fmt.Println("Finished getting phi...")
	if err != nil {
		t.Errorf("Could not generate private key!")
		return
	}

	dataToSign := StringToPartitionedData("TestDescription")

	sig := SignJohnsonRSA(rand.Reader, &dataToSign, priv_key, phi)
	if !sig.Verify(&dataToSign) {
		t.Errorf("Failed to verify initial data!")
		return
	}
	fmt.Println("Pure verification was successful")
	newChunks, newSig := sig.Redact([]int{1}, &dataToSign)
	if !newSig.Verify(&newChunks) {
		t.Errorf("Failed to verify redacted data!")
		return
	}
	fmt.Println("Redacted verification was successful")
	return
}
