package redactionschemes

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"strconv"
)

//As introduced in "Homomorphic Signature Schemes" from Johnson et al.

//GetNode traverses the tree by using bitstring: 0 is left, 1 is right

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

func (sig JohnsonRSASignature) Marshal() (string, error) {
	out_bytes, err := json.Marshal(johnsonRSASignatureSerialized{
		DocumentKey:   base64.StdEncoding.EncodeToString(sig.DocumentKey),
		BaseSignature: sig.BaseSignature.String(),
		Generator:     sig.Generator.String(),
		PublicKey:     base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&sig.PublicKey)),
	})
	return string(out_bytes), err
}

func UnmarshalJohnsonRSASignature(input string) (*JohnsonRSASignature, error) {
	var marshaled johnsonRSASignatureSerialized
	err := json.Unmarshal([]byte(input), &marshaled)
	if err != nil {
		return nil, err
	}
	DocumentKey, err := base64.StdEncoding.DecodeString(marshaled.DocumentKey)
	if err != nil {
		return nil, err
	}
	BaseSignature, succ := big.NewInt(0).SetString(marshaled.BaseSignature, 10)
	if !succ {
		return nil, fmt.Errorf("failed to parse BaseSignature as big.Int, %s", input)
	}
	Generator, succ := big.NewInt(0).SetString(marshaled.Generator, 10)
	if !succ {
		return nil, fmt.Errorf("failed to parse Generator as big.Int, %s", input)
	}
	PublicKeyBytes, err := base64.StdEncoding.DecodeString(marshaled.PublicKey)
	if err != nil {
		return nil, err
	}
	PublicKey, err := x509.ParsePKCS1PublicKey(PublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error while parsing PublicKey: %s", err)
	}
	out := JohnsonRSASignature{
		DocumentKey:   DocumentKey,
		BaseSignature: *BaseSignature,
		Generator:     *Generator,
		PublicKey:     *PublicKey,
	}
	return &out, nil
}

func newDetermRand(seed []byte) io.Reader {
	return &determRand{next: seed}
}

type determRand struct {
	next []byte
}

func (d *determRand) cycle() []byte {
	result := sha256.Sum256(d.next)
	d.next = result[:sha256.Size/2]
	return result[sha256.Size/2:]
}

func (d *determRand) Read(b []byte) (int, error) {
	n := 0
	for n < len(b) {
		out := d.cycle()
		n += copy(b[n:], out)
	}
	return n, nil
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
func SignJohnsonRSA(random io.Reader, x *PartitionedData, priv *rsa.PrivateKey, phi *big.Int) *JohnsonRSASignature {
	//fmt.Println("Beginning with generating coprime...")
	//v := GenerateCoPrime(random, phi)
	v := big.NewInt(int64(priv.E))
	//fmt.Println("Finished with generating coprime...")
	identifier := make([]byte, 16)
	mathrand.Read(identifier)
	//fmt.Println("Calculating hash...")
	hU := multHOrdered(x, identifier)
	//fmt.Println("Finished calculating hash...")
	//fmt.Println("Beginning with mod inverse...")
	hU.ModInverse(hU, phi)
	//fmt.Println("Finished with mod inverse...")
	var vExp big.Int
	vExp = *vExp.Exp(v, hU, priv.N)
	sig := JohnsonRSASignature{
		DocumentKey:   identifier,
		BaseSignature: vExp,
		Generator:     *v,
		PublicKey:     priv.PublicKey,
	}
	return &sig
}

//Redacts an existing signature by mutliplying it with the removed hashes
func (sig JohnsonRSASignature) Redact(RemovedIndices []int, x *PartitionedData) (*PartitionedData, *JohnsonRSASignature) {
	var temp big.Int
	var newV big.Int
	j := 0
	newX := make(PartitionedData, len(*x))
	redactX := make(PartitionedData, len(*x))
	for i, v := range *x {
		if j < len(RemovedIndices) && i == RemovedIndices[j] {
			redactX[i] = v
			newX[i] = []byte{}
			j++
		} else {
			redactX[i] = []byte{}
			newX[i] = v
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
	return &newX, &new_sig
}

//Verifies a signature according to the paper
func (sig JohnsonRSASignature) Verify(x *PartitionedData) bool {
	var v big.Int
	hash := multHOrdered(x, sig.DocumentKey)
	v.Exp(&sig.BaseSignature, hash, sig.PublicKey.N)
	return v.Cmp(&sig.Generator) == 0
}

func GetEulerPhi(priv *rsa.PrivateKey) *big.Int {
	one := big.NewInt(1)
	temp := big.NewInt(1)
	out := big.NewInt(1)
	for _, v := range priv.Primes {
		cur := temp.Sub(v, one)
		out.Mul(out, cur)
	}
	return out
}
