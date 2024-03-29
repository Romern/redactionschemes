package redactionschemes

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"

	"github.com/maruel/fortuna"
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

// From crypto/rand/util.go
// without mayberead to make this thing deterministic
func Prime(rand io.Reader, bits int) (*big.Int, error) {
	if bits < 2 {
		return nil, errors.New("crypto/rand: prime size must be at least 2-bit")
	}

	b := uint(bits % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, (bits+7)/8)
	p := new(big.Int)

	for {
		if _, err := io.ReadFull(rand, bytes); err != nil {
			return nil, err
		}

		// Clear bits in the first byte to make sure the candidate has a size <= bits.
		bytes[0] &= uint8(int(1<<b) - 1)
		// Don't let the value be too small, i.e, set the most significant two bits.
		// Setting the top two bits, rather than just the top bit,
		// means that when two of these values are multiplied together,
		// the result isn't ever one bit short.
		if b >= 2 {
			bytes[0] |= 3 << (b - 2)
		} else {
			// Here b==1, because b cannot be zero.
			bytes[0] |= 1
			if len(bytes) > 1 {
				bytes[1] |= 0x80
			}
		}
		// Make the value odd since an even number this large certainly isn't prime.
		bytes[len(bytes)-1] |= 1

		p.SetBytes(bytes)
		if p.ProbablyPrime(20) {
			return p, nil
		}
	}
}

// produces a hash for multiple chunks, based on prime numbers
func multHOrdered(Input *PartitionedData, Identifier []byte) *big.Int {
	bits := 256
	outNumber := big.NewInt(1)
	for i, v := range *Input {
		if len(v) != 0 {
			r, _ := Prime(fortuna.NewGenerator(sha256.New(), append(v, append(Identifier, []byte(strconv.Itoa(i))...)...)), bits)
			outNumber = outNumber.Mul(outNumber, r)
		}
	}
	return outNumber
}

// Signs the input data according to the paper
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

// Redacts an existing signature by mutliplying it with the removed hashes
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

// Verifies a signature according to the paper
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
