package redactionschemes

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	_ "image/png"
	"math/big"
)

type NaiveSignature struct {
	Identifier    []byte
	Length        int
	BaseSignature []byte
	Signatures    [][]byte
	PublicKey     ecdsa.PublicKey
}

type naiveSignatureSerialized struct {
	Identifier    string
	Length        int
	BaseSignature string
	Signature     []string
	PublicKey     string
}

func (sig *NaiveSignature) Verify(data *PartitionedData) error {
	if sig.Length != len(*data) {
		return fmt.Errorf("signature length does not match data lengh")
	}
	identifier_bytes := sig.Identifier
	length_bytes := big.NewInt(int64(len(*data))).Bytes()
	base_sig_hash := sha256.New()
	base_sig_hash.Write(length_bytes)
	base_sig_hash.Write(identifier_bytes)
	verified := ecdsa.VerifyASN1(&sig.PublicKey, base_sig_hash.Sum(nil), sig.BaseSignature)
	if !verified {
		return fmt.Errorf("verifying of base signature failed")
	}
	for i := 0; i < len(*data); i++ {
		if len((*data)[i]) != 0 {
			cur_sig_hash := sha256.New()
			cur_sig_hash.Write(identifier_bytes)
			cur_sig_hash.Write(big.NewInt(int64(i)).Bytes())
			cur_sig_hash.Write((*data)[i])
			verified := ecdsa.VerifyASN1(&sig.PublicKey, cur_sig_hash.Sum(nil), sig.Signatures[i])
			if !verified {
				return fmt.Errorf("verifying of a partition failed")
			}
		}
	}
	return nil
}

func (sig *NaiveSignature) Sign(data *PartitionedData, private_key *crypto.PrivateKey) error {
	ecdsa_private_key, ok := (*private_key).(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("only ECDSA supported atm")
	}
	//Create Identifier based on the hash of the input data:
	identifier_bytes := data.Hash()
	length_bytes := big.NewInt(int64(len(*data))).Bytes()

	base_sig_hash := sha256.New()
	base_sig_hash.Write(length_bytes)
	base_sig_hash.Write(identifier_bytes)
	signature, err := ecdsa.SignASN1(rand.Reader, ecdsa_private_key, base_sig_hash.Sum(nil))
	if err != nil {
		return err
	}
	signatures := make([][]byte, len(*data))
	for i := 0; i < len(*data); i++ {
		cur_sig_hash := sha256.New()
		cur_sig_hash.Write(identifier_bytes)
		cur_sig_hash.Write(big.NewInt(int64(i)).Bytes())
		cur_sig_hash.Write((*data)[i])
		cur_sig, err := ecdsa.SignASN1(rand.Reader, ecdsa_private_key, cur_sig_hash.Sum(nil))
		if err != nil {
			return err
		}
		signatures[i] = cur_sig
	}
	sig.Identifier = identifier_bytes
	sig.Length = len(*data)
	sig.BaseSignature = signature
	sig.Signatures = signatures
	sig.PublicKey = ecdsa_private_key.PublicKey
	return nil
}

func (sig *NaiveSignature) Redact(redacted_indices []int, data *PartitionedData) (RedactableSignature, error) {
	return sig, nil
}

func (sig *NaiveSignature) Marshal() (string, error) {
	signatures := make([]string, len(sig.Signatures))
	for i := 0; i < len(sig.Signatures); i++ {
		signatures[i] = base64.StdEncoding.EncodeToString(sig.Signatures[i])
	}
	marsh_pub_key, _ := x509.MarshalPKIXPublicKey(&sig.PublicKey)
	marsh := naiveSignatureSerialized{
		base64.StdEncoding.EncodeToString(sig.Identifier),
		sig.Length,
		base64.StdEncoding.EncodeToString(sig.BaseSignature),
		signatures,
		base64.StdEncoding.EncodeToString(marsh_pub_key),
	}
	out, err := json.Marshal(marsh)
	return string(out), err
}

func (sig *NaiveSignature) Unmarshal(sig_string string) error {
	var marsh naiveSignatureSerialized
	err := json.Unmarshal([]byte(sig_string), &marsh)
	if err != nil {
		return err
	}
	base_sig_bytes, err := base64.StdEncoding.DecodeString(marsh.BaseSignature)
	if err != nil {
		return err
	}
	identifier_bytes, err := base64.StdEncoding.DecodeString(marsh.Identifier)
	if err != nil {
		return err
	}
	signatures := make([][]byte, len(marsh.Signature))
	for i := 0; i < len(marsh.Signature); i++ {
		sig_bytes, err := base64.StdEncoding.DecodeString(marsh.Signature[i])
		if err != nil {
			return err
		}
		signatures[i] = sig_bytes
	}
	pub_bytes, err := base64.StdEncoding.DecodeString(marsh.PublicKey)
	if err != nil {
		return fmt.Errorf("error while decoding PublicKey bytes: %s", err)
	}
	pub, err := x509.ParsePKIXPublicKey(pub_bytes)
	if err != nil {
		return fmt.Errorf("error while parsing PublicKey: %s", err)
	}
	sig.Identifier = identifier_bytes
	sig.Length = marsh.Length
	sig.BaseSignature = base_sig_bytes
	sig.Signatures = signatures
	sig.PublicKey = *pub.(*ecdsa.PublicKey)
	return nil
}
