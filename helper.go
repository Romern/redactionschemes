package redactionschemes

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/draw"
	"image/jpeg"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

//PartitionedData is a wrapper for the input data to sign.
//Depending on the structure of the data at hand, you might want to choose a different partition:
//E.g. a partition for each field of a formular, or each word in a text.
//Depending on the signature scheme you use, the amount of partitions can have an impact on the size and performance.
type PartitionedData [][]byte

//RedactableSignature provides the interface for redactable signatures.
//
//Sign creates the initial signature for data using the private_key.
//Note, that not all schemes accept any type of private key.
//
//Redact creates a new signature, where the indices noted in redacted_indices are redacted.
//Note, that data of corse needs to contain the data which is beeing redacted.
//Note, that the new signature does not necessarily need to be new:
//e.g. with NaiveSignature, a redaction does not change the signature.
type RedactableSignature interface {
	Sign(data *PartitionedData, private_key *crypto.PrivateKey) error
	Redact(redacted_indices []int, data *PartitionedData) (RedactableSignature, error)
	Verify(data *PartitionedData) error
	Marshal() (string, error)
	Unmarshal(input string) error
}

//H defines the base cryptographic hash function, which is currently just SHA256.
//FIXME: Make this configurable?
func H(InputBytes []byte) []byte {
	seed_bytes := sha256.New()
	seed_bytes.Write(InputBytes)
	return seed_bytes.Sum(nil)
}

//Hash returns the SHA256 of the whole partitioned data.
func (c PartitionedData) Hash() []byte {
	seed_bytes := sha256.New()
	for _, v := range c {
		seed_bytes.Write(v)
	}
	return seed_bytes.Sum(nil)
}

//Redact creates a copy of the data where the indices in redacted_indices are redacted.
func (c PartitionedData) Redact(redacted_indices []int) (*PartitionedData, error) {
	new_chunk := make(PartitionedData, len(c))
	copy(new_chunk, c)
	for _, k := range redacted_indices {
		if k >= len(c) {
			return nil, fmt.Errorf("redacted index is out of range")
		}
		new_chunk[k] = []byte{}
	}
	return &new_chunk, nil
}

//Marshal creates a JSON/base64 encoded representation of the partitioned data.
func (c PartitionedData) Marshal() (string, error) {
	out_array := make([]string, len(c))
	for i, v := range c {
		out_array[i] = base64.StdEncoding.EncodeToString(v)
	}
	out_bytes, err := json.Marshal(out_array)
	return string(out_bytes), err
}

//UnmarshalPartitionedData unmarshales a JSON/base64 encoded representation of the partitioned data.
func UnmarshalPartitionedData(s string) (*PartitionedData, error) {
	var in_array []string
	var out PartitionedData
	err := json.Unmarshal([]byte(s), &in_array)
	if err != nil {
		return nil, err
	}
	out = make([][]byte, len(in_array))
	for i, v := range in_array {
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, err
		}
		out[i] = decoded
	}
	return &out, nil
}

//ToByteArray returns a one-dimensional slice of all partitions.
func (c PartitionedData) ToByteArray() []byte {
	out := make([]byte, 0)
	for _, v := range c {
		out = append(out, v...)
	}
	return out
}

//GetRedactedIndicesArray returns all indices of partitions where the bytecount is zero.
func (c PartitionedData) GetRedactedIndicesArray() []int {
	out := make([]int, 0)
	for i, v := range c {
		if len(v) == 0 {
			out = append(out, i)
		}
	}
	return out
}

//StringToPartitionedData partitions a string s word-wise
func StringToPartitionedData(s string) *PartitionedData {
	var out PartitionedData
	for _, v := range strings.Split(s, " ") {
		out = append(out, []byte(string(v)))
	}
	return &out
}

//Base64ImageToByteArray converts a base64-encoded image and converts it to a byte array.
func Base64ImageToByteArray(image_base64encoded string) ([]byte, error) {
	split_data := strings.Split(image_base64encoded, ",")
	if len(split_data) != 2 {
		return nil, fmt.Errorf("input string is not in a valid format, i.e. 'data:image/*;base64,*'")
	}
	if !strings.HasPrefix(image_base64encoded, "data:image/") || !strings.HasSuffix(split_data[0], "base64") {
		return nil, fmt.Errorf("format not correct, should start with 'data:image/*;base64,'")
	}
	return base64.StdEncoding.DecodeString(split_data[1])
}

//ToDataURLs will decode each partition as an data uri.
func (c PartitionedData) ToDataURLs() []string {
	out := make([]string, 0)
	for _, v := range c {
		contentType := http.DetectContentType(v)
		encoded := base64.StdEncoding.EncodeToString(v)
		out = append(out, "data:"+contentType+";base64,"+encoded)
	}
	return out
}

//ToDataURL converts the PartitionedData c with chunksX*chunksY image partitions into a whole base64-encoded data url.
func (c PartitionedData) ToDataURL(chunksX int, chunksY int) (string, error) {
	final_img, err := c.ToImage(chunksX, chunksY)
	if err != nil {
		return "data:image/empty;base64,", err
	}
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	err = jpeg.Encode(writer, final_img, &jpeg.Options{Quality: 100})
	if err != nil {
		return "", fmt.Errorf("error while encoding final jpeg: %s", err)
	}
	writer.Flush()
	buf_bytes := buf.Bytes()
	contentType := http.DetectContentType(buf_bytes)
	encoded := base64.StdEncoding.EncodeToString(buf_bytes)
	return "data:" + contentType + ";base64," + encoded, nil
}

//ToImage converts the PartitionedData c with chunksX*chunksY image partitions into a whole image.
func (c PartitionedData) ToImage(chunksX int, chunksY int) (image.Image, error) {
	img_chunks := make([]image.Image, len(c))
	for i, v := range c {
		if len(v) == 0 {
			empty_rect := image.Rectangle{image.Point{0, 0}, image.Point{0, 0}}
			empty_img := image.NewRGBA(empty_rect)
			img_chunks[i] = empty_img
		} else {
			image_data, _, err := image.Decode(bytes.NewReader(v))
			if err != nil {
				return nil, fmt.Errorf("error while decoding image: %s", err)
			}
			img_chunks[i] = image_data
		}
	}
	width := img_chunks[0].Bounds().Max.X
	height := img_chunks[0].Bounds().Max.Y
	rect := image.Rectangle{image.Point{0, 0}, image.Point{width * chunksX, height * chunksY}}
	final_img := image.NewRGBA(rect)
	for i := 0; i < chunksX; i++ {
		for j := 0; j < chunksY; j++ {
			cur_chunk := img_chunks[i*chunksX+j]
			cur_point := image.Rectangle{image.Point{width * i, height * j}, image.Point{width * (i + 1), height * (j + 1)}}
			draw.Draw(final_img, cur_point, cur_chunk, image.Point{0, 0}, draw.Src)
		}
	}
	return final_img, nil
}

//ImagetoPartitionedData converts a html-base64 encoded image into a chunk array with chunksX * chunksY resolution.
func ImageToPartitionedData(img image.Image, chunksX int, chunksY int) (*PartitionedData, error) {
	type subImager interface {
		SubImage(r image.Rectangle) image.Image
	}
	simage_data, ok := img.(subImager)
	if !ok {
		return nil, fmt.Errorf("image does not support cropping")
	}
	//Crop images into chunks:
	out := make(PartitionedData, chunksX*chunksY)
	width := img.Bounds().Max.X
	height := img.Bounds().Max.Y
	for i := 0; i < chunksX; i++ {
		for j := 0; j < chunksY; j++ {
			crop_rect := image.Rect((width/chunksX)*i, (height/chunksY)*j, (width/chunksX)*(i+1), (height/chunksY)*(j+1))
			cropped_img := simage_data.SubImage(crop_rect)
			//Use some encoding here, TODO: we maybe need to evaluate if JPEG at this size is ok-ish
			var buf bytes.Buffer
			writer := bufio.NewWriter(&buf)
			err := jpeg.Encode(writer, cropped_img, &jpeg.Options{Quality: 100})
			if err != nil {
				return nil, fmt.Errorf("error while encoding a chunk to jpeg: %s", err)
			}
			writer.Flush()
			out[i*chunksX+j] = buf.Bytes()
		}
	}
	return &out, nil
}

//CommaSeperatedIndicesArray takes a comma seperated string of indices and converts it into a slice of indices.
func CommaSeperatedIndicesArray(s string) ([]int, error) {
	mismatch_s := strings.Split(s, ",")
	mismatches := make([]int, 0)
	for _, v := range mismatch_s {
		int_s, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("could not parse an index: %s", err.Error())
		}
		mismatches = append(mismatches, int_s)
	}
	return mismatches, nil
}

//test signs, verifies, redacts, and verifies again.
func test(t *testing.T, private_key crypto.PrivateKey, sig RedactableSignature) {
	cur_string := ""
	for i := 0; i < 100; i++ {
		dataToSign := StringToPartitionedData(cur_string)

		err := sig.Sign(dataToSign, &private_key)
		if err != nil {
			t.Errorf("Failed to sign data! %s", err)
			return
		}
		if err := sig.Verify(dataToSign); err != nil {
			t.Errorf("Failed to verify initial data! %s", err)
			return
		}

		newSig, err := sig.Redact([]int{0}, dataToSign)
		if err != nil {
			t.Errorf("Failed to redact signature! %s", err)
			return
		}
		newChunks, err := dataToSign.Redact([]int{0})
		if err != nil {
			t.Errorf("Failed to redact data! %s", err)
			return
		}
		if err := newSig.Verify(newChunks); err != nil {
			t.Errorf("Failed to verify redacted data! %s", err)
			return
		}
		cur_string += "A "
	}
}
