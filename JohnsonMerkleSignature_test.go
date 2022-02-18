package redactionschemes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestJohnsonMerkleSignature(t *testing.T) {
	priv_key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("Could not generate private key!")
		return
	}

	dataToSign := StringToPartitionedData("TestDescription")

	sig, err := SignJohnsonSignature(&dataToSign, priv_key)
	if err != nil {
		t.Errorf("Could not sign data!")
		return
	}

	marshaled, err := sig.Marshal()
	if err != nil {
		t.Errorf("(No redaction) marshaling failed! %s", err)
		return
	}
	unmarshaled_sig, err := UnmarshalJohnsonMerkleSignature(marshaled)
	if err != nil {
		t.Errorf("(No redaction) unmarshaling failed! %s", err)
		return
	}

	err = unmarshaled_sig.Verify(&dataToSign)
	if err != nil {
		t.Errorf("(No redaction) verification failed! %s", err)
		return
	}

	mismatches := map[int]bool{0: true, 1: true, 5: true}
	new_data, err := dataToSign.Redact(mismatches)
	if err != nil {
		t.Errorf("redaction failed! %s", err)
		return
	}

	new_sig, err := unmarshaled_sig.Redact(&dataToSign, mismatches)
	if err != nil {
		t.Errorf("redaction failed! %s", err)
		return
	}

	marshaled_new, err := new_sig.Marshal()
	if err != nil {
		t.Errorf("Failed to marshal signature")
		return
	}
	unmarshaled_sig_new, err := UnmarshalJohnsonMerkleSignature(marshaled_new)
	if err != nil {
		t.Errorf("Failed to unmarshal signature")
		return
	}

	err = unmarshaled_sig_new.Verify(new_data)
	if err != nil {
		t.Errorf("(Redacted) verification failed!")
		return
	}
	println("(Redacted) EVERYTHING'S FINE!")
}
