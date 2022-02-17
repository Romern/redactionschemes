package redactionschemes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
)

func testJohnson() {
	priv_key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		println("Could not generate private key!")
	}

	dataToSign := StringToPartitionedData("TestDescription")

	sig := SignJohnsonSignature(&dataToSign, priv_key)

	marshaled, err := sig.Marshal()
	unmarshaled_sig, err := UnmarshalJohnsonSignature(marshaled)

	err = unmarshaled_sig.Verify(&dataToSign)
	if err != nil {
		println("(No redaction) verification failed!")
		return
	}

	mismatches := map[int]bool{0: true, 1: true, 5: true}
	new_data, err := dataToSign.Redact(mismatches)

	new_sig, err := unmarshaled_sig.Redact(&dataToSign, mismatches)

	marshaled_new, err := new_sig.Marshal()
	if err != nil {
		println("Failed to marshal signature")
		return
	}
	unmarshaled_sig_new, err := UnmarshalJohnsonSignature(marshaled_new)
	if err != nil {
		println("Failed to unmarshal signature")
		return
	}

	err = unmarshaled_sig_new.Verify(new_data)
	if err != nil {
		println("(Redacted) verification failed!")
	} else {
		println("(Redacted) EVERYTHING'S FINE!")
	}
}

func testJohnsonRSA() {
	priv_key, err := rsa.GenerateKey(rand.Reader, 2048)
	fmt.Println("Getting phi...")
	phi := GetEulerPhi(priv_key)
	fmt.Println("Finished getting phi...")
	if err != nil {
		println("Could not generate private key!")
	}

	dataToSign := StringToPartitionedData("TestDescription")

	sig := SignJohnsonRSA(rand.Reader, &dataToSign, priv_key, phi)
	if !sig.Verify(&dataToSign) {
		fmt.Println("fudge")
		os.Exit(1)
	}
	fmt.Println("Pure verification was successful")
	newChunks, newSig := sig.Redact([]int{1}, &dataToSign)
	if !newSig.Verify(&newChunks) {
		fmt.Println("fudge redact")
		os.Exit(1)
	}
	fmt.Println("Redacted verification was successful")
}

func testNaive() {
	priv_key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		println("Could not generate private key!")
	}

	dataToSign := StringToPartitionedData("TestDescription")

	sig, err := SignNaivSignature(&dataToSign, priv_key)
	if err != nil {
		fmt.Printf("Failed to Sign! %s", err.Error())
		return
	}

	marshaled, err := sig.Marshal()
	unmarshaled_sig, err := UnmarshalNaiveSignature(marshaled)

	err = unmarshaled_sig.Verify(&dataToSign)
	if err != nil {
		fmt.Printf("Failed to Verify (unredacted)! %s", err.Error())
		return
	}

	mismatches := map[int]bool{0: true, 1: true, 5: true}
	new_data, err := dataToSign.Redact(mismatches)

	err = unmarshaled_sig.Verify(new_data)
	if err != nil {
		fmt.Printf("Failed to Verify (redacted)! %s", err.Error())
		return
	} else {
		println("(Redacted) EVERYTHING'S FINE!")
	}
}

func main() {
	fmt.Println("ay")
}
