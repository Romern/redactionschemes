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

	dataToSign := StringToPartitionedData("TestDescription")

	sig, err := SignNaivSignature(&dataToSign, priv_key)
	if err != nil {
		t.Errorf("Failed to Sign! %s", err.Error())
		return
	}

	marshaled, err := sig.Marshal()
	if err != nil {
		t.Errorf("Failed to Marshal signature (unredacted)! %s", err.Error())
		return
	}
	unmarshaled_sig, err := UnmarshalNaiveSignature(marshaled)
	if err != nil {
		t.Errorf("Failed to Unmarshal signature (unredacted)! %s", err.Error())
		return
	}

	err = unmarshaled_sig.Verify(&dataToSign)
	if err != nil {
		t.Errorf("Failed to Verify (unredacted)! %s", err.Error())
		return
	}

	mismatches := map[int]bool{0: true, 1: true, 5: true}
	new_data, err := dataToSign.Redact(mismatches)
	if err != nil {
		t.Errorf("Failed to redact! %s", err.Error())
		return
	}

	err = unmarshaled_sig.Verify(new_data)
	if err != nil {
		t.Errorf("Failed to Verify (redacted)! %s", err.Error())
		return
	}
}
