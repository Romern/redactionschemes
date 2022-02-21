package redactionschemes

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	_ "image/png"
	"math"
	mathrand "math/rand"
	"math/bits"
	"sort"
	"strconv"
)

//As introduced in "Homomorphic Signature Schemes" from Johnson et al.

type JohnsonMerkleSignature struct {
	BaseSignature []byte
	PublicKey     ecdsa.PublicKey
	Key           []byte                      // This is only visible before the redaction
	RedactedKeys  map[string]redactedProperty // And this afterwards, these are the conodes keys
	RedactedHash  map[string]redactedProperty // and these the hashes of the parents of the redacted nodes
}

type johnsonNode struct {
	Children map[int]*johnsonNode
	Parent   *johnsonNode
	Key      []byte
	Hash     []byte
	Position string
	Deleted  bool
}

type redactedProperty struct {
	Key      []byte
	Hash     []byte
	Position string
}

//Length-doubling pseudorandom generator
func G(InputBytes []byte) []byte {
	//Hash the bytes of the input to get a fixed length byte array
	seed_bytes := sha256.New()
	seed_bytes.Write(InputBytes)
	//only use the first 8 bytes, as more is not supported
	seed := int64(binary.BigEndian.Uint64(seed_bytes.Sum(nil)[:8]))

	mathrand.Seed(seed)
	prn := make([]byte, len(InputBytes)*2)
	mathrand.Read(prn)
	return prn
}

func bitStringToIndex(bitstring string, length int) int {
	is_power_of_two := ((length & (length - 1)) == 0)
	if is_power_of_two || bitstring[0] == '0' {
		//only works if all leafs on bottom depth, i.e. length power of 2
		i, _ := strconv.ParseInt(bitstring, 2, 64)
		return int(i)
	}
	//bitstring[0] == '1', i.e. right site of the tree and possibly partial
	i := bits.RotateLeft(1, bits.Len(uint(length))-1)
	irest, _ := strconv.ParseInt(bitstring[1:], 2, 64)
	return int(i) + int(irest)
}

func isLowestLevel(bitstring string, length int) bool {
	bit_length := bits.Len(uint(length))
	max_size := int(bits.RotateLeft(1, bit_length-1))
	return length == 1 || (bit_length == len(bitstring) || bitStringToIndex(bitstring+"0", length) >= max_size)
}

//generateRedactionTree recursively generates the redaction tree
func generateRedactionTree(parent *johnsonNode, data *PartitionedData) *johnsonNode {
	// if depth is lowest (does not necessarily need to be 0)
	if len(*data) == 1 || isLowestLevel(parent.Position, len(*data)) {
		// we are now at the leaf node and go back up the tree, so we set the data to the leafs
		parent.Hash = H(append([]byte{0}, append(parent.Key, (*data)[bitStringToIndex(parent.Position, len(*data))]...)...))
		return parent
	}
	new_seed := G(parent.Key)

	left_position := parent.Position + "0"
	left_node := johnsonNode{
		Key:      new_seed[:len(parent.Key)],
		Parent:   parent,
		Position: left_position}
	left := generateRedactionTree(&left_node,
		data)

	right_position := parent.Position + "1"
	right_node := johnsonNode{
		Key:      new_seed[len(parent.Key):],
		Parent:   parent,
		Position: right_position}
	right := generateRedactionTree(&right_node,
		data)

	parent.Children = map[int]*johnsonNode{0: left, 1: right}
	// Now we can calculate the hash value of the leafs merkle-tree-style
	parent.Hash = H(append([]byte{1}, append(left.Hash, right.Hash...)...))
	return parent
}

//calculateHashes recursively calculates the hashes of a tree with partial information
func calculateHashes(node_bitstring string, redactedKeys map[string]redactedProperty, redactedHash map[string]redactedProperty, data *PartitionedData) {
	if _, ok := redactedHash[node_bitstring]; ok {
		//The node was redacted and we already have the hash
		return
	}

	if isLowestLevel(node_bitstring, len(*data)) {
		//We are at the lowest level and need to calculate the leaf hash from the data and key
		prop := redactedKeys[node_bitstring]
		prop.Hash = H(append([]byte{0},
			append(redactedKeys[node_bitstring].Key, (*data)[bitStringToIndex(node_bitstring, len(*data))]...)...))
		redactedHash[node_bitstring] = prop
		return
	}

	//Do this for all child nodes
	calculateHashes(node_bitstring+"0", redactedKeys, redactedHash, data)
	calculateHashes(node_bitstring+"1", redactedKeys, redactedHash, data)

	//Else, we just calculate the hash normally using the possibly two child nodes
	prop := redactedKeys[node_bitstring]

	prop.Hash = H(append([]byte{1},
		append(redactedHash[node_bitstring+"0"].Hash,
			redactedHash[node_bitstring+"1"].Hash...)...))
	redactedHash[node_bitstring] = prop
}

//Verifies if a given signature matches the supplied data
//This rebuilds the tree by regenerating the co-node-trees, as well as using the supplied hashes to retrieve the root node hash
func (sig *JohnsonMerkleSignature) Verify(data *PartitionedData) error {
	//This is the case when the signature is initial, so we have the root key included and can simply verify everything
	if sig.Key != nil && len(sig.Key) > 0 {
		main_node := johnsonNode{
			Key:      sig.Key,
			Position: ""}
		tree := generateRedactionTree(&main_node, data)
		if !ecdsa.VerifyASN1(&sig.PublicKey, tree.Hash, sig.BaseSignature) {
			return fmt.Errorf("verification failed! (initial signature)")
		} else {
			return nil
		}
	}
	//Else, we need to build the partial tree by using RedactedKeys and RedactedHash

	//First step: sig.RedactedKeys contains all relevant co-nodes, which we need to compute in order from lowest depth to highest, so we sort it:
	positions := make([]string, 0, len(sig.RedactedKeys))
	for k := range sig.RedactedKeys {
		positions = append(positions, k)
	}
	//Our positions slice is sorted by depth, and we need to start at the lowest depth, so we need to reverse it
	sort.Slice(positions, func(i, j int) bool {
		return len(positions[i]) > len(positions[j])
	})
	//Second step: Calculate the hashes of the co-nodes by building the partial redaction tree

	for _, v := range positions {
		cur_key := sig.RedactedKeys[v]

		//co-nodes have a full partial tree, so calculate it first
		cur_node := johnsonNode{
			Key:      cur_key.Key,
			Position: cur_key.Position}
		tree := generateRedactionTree(&cur_node, data)

		cur_key.Hash = tree.Hash
		sig.RedactedHash[v] = cur_key
	}

	//Recursively retrive the hash of the other node. We should have all the relevant info at this point
	calculateHashes("", sig.RedactedKeys, sig.RedactedHash, data)

	//Third step: Verify signature
	if !ecdsa.VerifyASN1(&sig.PublicKey, sig.RedactedHash[""].Hash, sig.BaseSignature) {
		return fmt.Errorf("verification failed! (rebuild tree)")
	} else {
		return nil
	}
}

//pruneRedactionTree adds all relevant tree nodes needed for the redaction to redactedHashes based on if they are pruned
func pruneRedactionTree(mismatches map[int]bool, node *johnsonNode, redactedHashes map[string]*johnsonNode, data_length int) {
	lowest_level := isLowestLevel(node.Position, data_length)
	if lowest_level && mismatches[int(bitStringToIndex(node.Position, data_length))] {
		redactedHashes[node.Position] = node
		return
	}

	for _, v := range node.Children {
		pruneRedactionTree(mismatches, v, redactedHashes, data_length)
	}

	if !lowest_level {
		_, leftChildIn := redactedHashes[node.Children[0].Position]
		_, rightChildIn := redactedHashes[node.Children[1].Position]
		if leftChildIn && rightChildIn {
			redactedHashes[node.Position] = node
			delete(redactedHashes, node.Children[0].Position)
			delete(redactedHashes, node.Children[1].Position)
		}
	}
}

//Redacts an existing signature based on data.
//When redacting, k_epsilon is not publicsed, as with it we could just calculate all the hashes
//and possibly get access to the redacted data by bruteforcing or similar.
//Instead, we just publicise the co-nodes keys, as well as the parent node of the redacted leaf
func (orig_signature *JohnsonMerkleSignature) Redact(redacted_indices []int, data *PartitionedData) (RedactableSignature, error) {
	something_is_redacted := len(redacted_indices) > 0
	if !something_is_redacted {
		return orig_signature, nil
	}
	err := orig_signature.Verify(data)
	if err != nil {
		return nil, fmt.Errorf("data does not match the orig_signature! %s", err)
	}

	if orig_signature.Key == nil || len(orig_signature.Key) == 0 {
		return nil, fmt.Errorf("CURRENTLY REDACTING REDACTED SIGNATURES IS NOT SUPPORTED! Key empty")
	}

	node := johnsonNode{
		Key:      orig_signature.Key,
		Position: ""}
	tree := generateRedactionTree(&node, data)

	if orig_signature.RedactedHash != nil && len(orig_signature.RedactedHash) > 0 {
		//TODO: It should  be possible to further redact a redaction
		return nil, fmt.Errorf("CURRENTLY REDACTING REDACTED SIGNATURES IS NOT SUPPORTED! Redacted Hash not empty")
	}

	redactedKeys := make(map[string]redactedProperty)
	redactedHash := make(map[string]redactedProperty)
	redactedNodes := make(map[string]*johnsonNode)
	redacted_chunks := make(map[int]bool)
	for _, v := range redacted_indices {
		redacted_chunks[v] = true
	}

	//Check for consecutive redactions:
	//If all children of a node are redacted, we just give the hash of the parent.
	//We do this by pruning the nodes from the tree, starting at the lowest level.
	pruneRedactionTree(redacted_chunks, tree, redactedNodes, len(*data))

	//Retrive Conodes by going up the tree
	for _, node := range redactedNodes {
		if node.Hash == nil || len(node.Hash) == 0 {
			return nil, fmt.Errorf("some redacted node's hash seems to be empty")
		}
		//Prepare final datastructure
		redactedHash[node.Position] = redactedProperty{Hash: node.Hash, Position: node.Position}
		//Go up the tree and retrive the co-nodes
		cur := node
		for cur.Parent != nil {
			pos, _ := strconv.Atoi(cur.Position[len(cur.Position)-1:])
			pos = 1 - pos
			redactedKeys[cur.Parent.Children[pos].Position] = redactedProperty{
				Key:      cur.Parent.Children[pos].Key,
				Position: cur.Parent.Children[pos].Position}
			cur = cur.Parent
		}
	}

	//Remove the keys of the nodes which are already included as hashes
	for v := range redactedHash {
		delete(redactedKeys, v)
	}

	//Remove the redundant co-nodes which include all necessary hashes in their children, i.e. one of their prefixes is also in redactkeys
	//As we modify the map while we iterate over it, we create a copy beforehand
	redactedKeysCopy := make(map[string]redactedProperty)

	for k, v := range redactedKeys {
		redactedKeysCopy[k] = v
	}

	for v := range redactedKeysCopy {
		_, ok0 := redactedKeysCopy[v+"0"]
		_, ok1 := redactedKeysCopy[v+"1"]
		if ok0 || ok1 {
			delete(redactedKeys, v)
		}
	}
	out := JohnsonMerkleSignature{
		BaseSignature: orig_signature.BaseSignature,
		PublicKey:     orig_signature.PublicKey,
		RedactedKeys:  redactedKeys,
		RedactedHash:  redactedHash}

	return &out, nil
}

//Sign uses the private_key to sign data redactably.
func (sig *JohnsonMerkleSignature) Sign(data *PartitionedData, private_key *crypto.PrivateKey) error {
	ecdsa_private_key, ok := (*private_key).(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("only ECDSA supported atm")
	}

	prn := data.Hash()

	node := johnsonNode{
		Key:      prn,
		Position: ""}
	tree := generateRedactionTree(&node, data)
	signature, _ := ecdsa.SignASN1(rand.Reader, ecdsa_private_key, tree.Hash)
	sig.BaseSignature = signature
	sig.PublicKey = ecdsa_private_key.PublicKey
	sig.Key = prn
	sig.RedactedHash = nil
	sig.RedactedKeys = nil
	return nil
}

type redactedPropertySerialized struct {
	Key      string
	Hash     string
	Position string
}

type johnsonRedactableSignatureSerialized struct {
	BaseSignature string
	PublicKey     string
	Key           string
	RedactedKeys  map[string]redactedPropertySerialized
	RedactedHash  map[string]redactedPropertySerialized
}

func (sig *JohnsonMerkleSignature) Marshal() (string, error) {
	redacted_keys := make(map[string]redactedPropertySerialized)
	for k, v := range sig.RedactedKeys {
		redacted_keys[k] = redactedPropertySerialized{
			Key:      base64.StdEncoding.EncodeToString(v.Key),
			Hash:     base64.StdEncoding.EncodeToString(v.Hash),
			Position: v.Position,
		}
	}
	redacted_hash := make(map[string]redactedPropertySerialized)
	for k, v := range sig.RedactedHash {
		redacted_hash[k] = redactedPropertySerialized{
			Key:      base64.StdEncoding.EncodeToString(v.Key),
			Hash:     base64.StdEncoding.EncodeToString(v.Hash),
			Position: v.Position,
		}
	}
	marsh_pub_key, _ := x509.MarshalPKIXPublicKey(&sig.PublicKey)

	out := johnsonRedactableSignatureSerialized{
		BaseSignature: base64.StdEncoding.EncodeToString(sig.BaseSignature),
		PublicKey:     base64.StdEncoding.EncodeToString(marsh_pub_key),
		Key:           base64.StdEncoding.EncodeToString(sig.Key),
		RedactedKeys:  redacted_keys,
		RedactedHash:  redacted_hash,
	}

	out_bytes, err := json.Marshal(out)
	return string(out_bytes), err
}

func (sig *JohnsonMerkleSignature) Unmarshal(input string) error {
	var sig_serialized johnsonRedactableSignatureSerialized
	err := json.Unmarshal([]byte(input), &sig_serialized)
	if err != nil {
		sig_string_unquote, _ := strconv.Unquote(input)
		err := json.Unmarshal([]byte(sig_string_unquote), &sig_serialized)
		if err != nil {
			return fmt.Errorf("error while unmarshaling serialized Signature: %s: %s", err, input)
		}
	}
	redacted_keys := make(map[string]redactedProperty)
	for k, v := range sig_serialized.RedactedKeys {
		key, err := base64.StdEncoding.DecodeString(v.Key)
		if err != nil {
			return fmt.Errorf("error while decoding Key: %s", err)
		}
		hash, err := base64.StdEncoding.DecodeString(v.Hash)
		if err != nil {
			return fmt.Errorf("error while decoding Hash: %s", err)
		}
		redacted_keys[k] = redactedProperty{
			Key:      key,
			Hash:     hash,
			Position: v.Position,
		}
	}
	redacted_hash := make(map[string]redactedProperty)
	for k, v := range sig_serialized.RedactedHash {
		key, err := base64.StdEncoding.DecodeString(v.Key)
		if err != nil {
			return fmt.Errorf("error while decoding Key: %s", err)
		}
		hash, err := base64.StdEncoding.DecodeString(v.Hash)
		if err != nil {
			return fmt.Errorf("error while decoding Hash: %s", err)
		}
		redacted_hash[k] = redactedProperty{
			Key:      key,
			Hash:     hash,
			Position: v.Position,
		}
	}

	base_sig, err := base64.StdEncoding.DecodeString(sig_serialized.BaseSignature)
	if err != nil {
		return fmt.Errorf("error while decoding BaseSignature: %s", err)
	}
	pub_bytes, err := base64.StdEncoding.DecodeString(sig_serialized.PublicKey)
	if err != nil {
		return fmt.Errorf("error while decoding PublicKey bytes: %s", err)
	}
	pub, err := x509.ParsePKIXPublicKey(pub_bytes)
	if err != nil {
		return fmt.Errorf("error while parsing PublicKey: %s", err)
	}

	key, err := base64.StdEncoding.DecodeString(sig_serialized.Key)
	if err != nil {
		return fmt.Errorf("error while decoding Key: %s", err)
	}

	sig.BaseSignature = base_sig
	sig.PublicKey = *pub.(*ecdsa.PublicKey)
	sig.Key = key
	sig.RedactedKeys = redacted_keys
	sig.RedactedHash = redacted_hash

	return nil
}
