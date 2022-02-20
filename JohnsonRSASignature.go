package redactionschemes

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"strconv"
)

//As introduced in "Homomorphic Signature Schemes" from Johnson et al.

type JohnsonRSASignature struct {
	DocumentKey   []byte
	BaseSignature big.Int
	Generator     big.Int
	PublicKey     rsa.PublicKey
}

type johnsonRSASignatureSerialized struct {
	DocumentKey   string
	BaseSignature string
	Generator     string
	PublicKey     string
}

func (sig *JohnsonRSASignature) Marshal() (string, error) {
	out_bytes, err := json.Marshal(johnsonRSASignatureSerialized{
		DocumentKey:   base64.StdEncoding.EncodeToString(sig.DocumentKey),
		BaseSignature: sig.BaseSignature.String(),
		Generator:     sig.Generator.String(),
		PublicKey:     base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&sig.PublicKey)),
	})
	return string(out_bytes), err
}

func (sig *JohnsonRSASignature) Unmarshal(input string) error {
	var marshaled johnsonRSASignatureSerialized
	err := json.Unmarshal([]byte(input), &marshaled)
	if err != nil {
		return err
	}
	DocumentKey, err := base64.StdEncoding.DecodeString(marshaled.DocumentKey)
	if err != nil {
		return err
	}
	BaseSignature, succ := big.NewInt(0).SetString(marshaled.BaseSignature, 10)
	if !succ {
		return fmt.Errorf("failed to parse BaseSignature as big.Int, %s", input)
	}
	Generator, succ := big.NewInt(0).SetString(marshaled.Generator, 10)
	if !succ {
		return fmt.Errorf("failed to parse Generator as big.Int, %s", input)
	}
	PublicKeyBytes, err := base64.StdEncoding.DecodeString(marshaled.PublicKey)
	if err != nil {
		return err
	}
	PublicKey, err := x509.ParsePKCS1PublicKey(PublicKeyBytes)
	if err != nil {
		return fmt.Errorf("error while parsing PublicKey: %s", err)
	}
	sig.DocumentKey = DocumentKey
	sig.BaseSignature = *BaseSignature
	sig.Generator = *Generator
	sig.PublicKey = *PublicKey
	return nil
}

//produces a hash for multiple chunks, based on prime numbers
func multHOrdered(Input *PartitionedData, Identifier []byte) *big.Int {
	bits := 256
	outNumber := big.NewInt(1)
	for i, v := range *Input {
		if len(v) != 0 {
			data := sha256.Sum256(append(v, append(Identifier, []byte(strconv.Itoa(i))...)...))
			data_uint := binary.LittleEndian.Uint64(data[:])
			r, _ := rand.Prime(mathrand.New(mathrand.NewSource(int64(data_uint))), bits)
			outNumber = outNumber.Mul(outNumber, r)
		}
	}
	return outNumber
}

//Signs the input data according to the paper
func (sig *JohnsonRSASignature) Sign(data *PartitionedData, private_key *crypto.PrivateKey) error {
	rsa_private_key, ok := (*private_key).(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("only RSA supported atm")
	}

	phi := getEulerPhi(rsa_private_key)
	//fmt.Println("Beginning with generating coprime...")
	//v := GenerateCoPrime(random, phi)
	v := big.NewInt(int64(rsa_private_key.E))
	//fmt.Println("Finished with generating coprime...")
	identifier_bytes := data.Hash()
	//fmt.Println("Calculating hash...")
	hU := multHOrdered(data, identifier_bytes)
	//fmt.Println("Finished calculating hash...")
	//fmt.Println("Beginning with mod inverse...")
	hU.ModInverse(hU, phi)
	//fmt.Println("Finished with mod inverse...")
	var vExp big.Int
	vExp = *vExp.Exp(v, hU, rsa_private_key.N)
	sig.DocumentKey = identifier_bytes
	sig.BaseSignature = vExp
	sig.Generator = *v
	sig.PublicKey = rsa_private_key.PublicKey
	return nil
}

//Redacts an existing signature by mutliplying it with the removed hashes
func (sig *JohnsonRSASignature) Redact(redacted_indices []int, data *PartitionedData) (RedactableSignature, error) {
	var temp big.Int
	var newV big.Int
	j := 0
	redactX := make(PartitionedData, len(*data))
	for i, v := range *data {
		if j < len(redacted_indices) && i == redacted_indices[j] {
			redactX[i] = v
			j++
		} else {
			redactX[i] = []byte{}
		}
	}
	hash := multHOrdered(&redactX, sig.DocumentKey)
	newV = *temp.Exp(&sig.BaseSignature, hash, sig.PublicKey.N)
	new_sig := JohnsonRSASignature{
		DocumentKey:   sig.DocumentKey,
		BaseSignature: newV,
		Generator:     sig.Generator,
		PublicKey:     sig.PublicKey,
	}
	return &new_sig, nil
}

//Verifies a signature according to the paper
func (sig *JohnsonRSASignature) Verify(data *PartitionedData) error {
	var v big.Int
	hash := multHOrdered(data, sig.DocumentKey)
	v.Exp(&sig.BaseSignature, hash, sig.PublicKey.N)
	if v.Cmp(&sig.Generator) == 0 {
		return nil
	}
	return fmt.Errorf("failed to verify: base signature does not match data")
}

func getEulerPhi(priv *rsa.PrivateKey) *big.Int {
	one := big.NewInt(1)
	temp := big.NewInt(1)
	out := big.NewInt(1)
	for _, v := range priv.Primes {
		cur := temp.Sub(v, one)
		out.Mul(out, cur)
	}
	return out
}
