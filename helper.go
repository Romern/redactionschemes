package redactionschemes

import (
	"bufio"
	"bytes"
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
)

type PartitionedData [][]byte

//Cryptographic hash function (just sha256)
func H(InputBytes []byte) []byte {
	seed_bytes := sha256.New()
	seed_bytes.Write(InputBytes)
	return seed_bytes.Sum(nil)
}

func (c PartitionedData) Hash() []byte {
	seed_bytes := sha256.New()
	for _, v := range c {
		seed_bytes.Write(v)
	}
	return seed_bytes.Sum(nil)
}

func (c PartitionedData) Redact(mismatches map[int]bool) (*PartitionedData, error) {
	new_chunk := make(PartitionedData, len(c))
	copy(new_chunk, c)
	for k := range mismatches {
		if k >= len(c) {
			return &new_chunk, nil
			//return nil, fmt.Errorf("Mismatch index is out of range!")
		}
		if mismatches[k] {
			new_chunk[k] = []byte{}
		}
	}
	return &new_chunk, nil
}

func (c PartitionedData) Marshal() (string, error) {
	out_array := make([]string, len(c))
	for i, v := range c {
		out_array[i] = base64.StdEncoding.EncodeToString(v)
	}
	out_bytes, err := json.Marshal(out_array)
	return string(out_bytes), err
}

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

func (c PartitionedData) ToByteArray() []byte {
	out := make([]byte, 0)
	for _, v := range c {
		out = append(out, v...)
	}
	return out
}

func (c PartitionedData) ToHTMLString() string {
	//TODO: Unsafe, users could inject code easily
	var out string
	for _, v := range c {
		if len(v) == 0 {
			out += "&#9635;"
		} else {
			out += string(v) + " "
		}
	}
	return out
}

func (c PartitionedData) GetRedactedIndicesArray() []int {
	out := make([]int, 0)
	for i, v := range c {
		if len(v) == 0 {
			out = append(out, i)
		}
	}
	return out
}

func (c PartitionedData) GetRedactedIndicesArrayImage(chunkX, chunkY int) []int {
	out := make([]int, 0)
	for i, v := range c {
		if i >= chunkX*chunkY {
			//ignore scaling of johnson
			return out
		}
		if len(v) == 0 {
			out = append(out, i)
		}
	}
	return out
}

//StringToPartitionedData converts a string s to a chunk array word-wise
func StringToPartitionedData(s string) PartitionedData {
	var out PartitionedData
	for _, v := range strings.Split(s, " ") {
		out = append(out, []byte(string(v)))
	}
	return out
}

func Base64ImageToByteArray(image_base64encoded string) ([]byte, error) {
	split_data := strings.Split(image_base64encoded, ",")
	if len(split_data) != 2 {
		return nil, fmt.Errorf("Input string is not in a valid format, i.e. data:image/*;base64,*")
	}
	if !strings.HasPrefix(image_base64encoded, "data:image/") || !strings.HasSuffix(split_data[0], "base64") {
		return nil, fmt.Errorf("Format not correct, should start with 'data:image/*;base64,")
	}
	return base64.StdEncoding.DecodeString(split_data[1])
}

//ToDataURLs will decode each image chunk, as we need reproducability at the end
//The client has to stitch together the image if this is used
func (c PartitionedData) ToDataURLs() []string {
	out := make([]string, 0)
	for _, v := range c {
		contentType := http.DetectContentType(v)
		encoded := base64.StdEncoding.EncodeToString(v)
		out = append(out, "data:"+contentType+";base64,"+encoded)
	}
	return out
}

func (c PartitionedData) ToDataURL(chunksX int, chunksY int) (string, error) {
	final_img, err := c.ToImage(chunksX, chunksY)
	if err != nil {
		return "data:image/empty;base64,", err
	}
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	err = jpeg.Encode(writer, final_img, &jpeg.Options{Quality: 100})
	if err != nil {
		return "", fmt.Errorf("Error while encoding final jpeg: %s", err)
	}
	writer.Flush()
	buf_bytes := buf.Bytes()
	contentType := http.DetectContentType(buf_bytes)
	encoded := base64.StdEncoding.EncodeToString(buf_bytes)
	return "data:" + contentType + ";base64," + encoded, nil
}

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
				return nil, fmt.Errorf("Error while decoding image: %s", err)
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
func ImageToPartitionedData(img image.Image, chunksX int, chunksY int) (PartitionedData, error) {
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
				return nil, fmt.Errorf("Error while encoding a chunk to jpeg: %s", err)
			}
			writer.Flush()
			out[i*chunksX+j] = buf.Bytes()
		}
	}
	return out, nil
}

func CommaSeperatedIndicesToMismatchesMap(s string) (map[int]bool, error) {
	mismatch_s := strings.Split(s, ",")
	mismatches := make(map[int]bool)
	for _, v := range mismatch_s {
		int_s, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("Could not parse an index: %s", err.Error())
		}
		mismatches[int_s] = true
	}
	return mismatches, nil
}

func CommaSeperatedIndicesArray(s string) ([]int, error) {
	mismatch_s := strings.Split(s, ",")
	mismatches := make([]int, 0)
	for _, v := range mismatch_s {
		int_s, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("Could not parse an index: %s", err.Error())
		}
		mismatches = append(mismatches, int_s)
	}
	return mismatches, nil
}

func CommaSeperatedIndicesToBoolMatrix(s string, m, n int) ([][]bool, error) {
	indices := strings.Split(s, ",")
	outputMatrix := make([][]bool, m)
	for i := 0; i < m; i++ {
		outputMatrix[i] = make([]bool, n)
	}
	for _, v := range indices {
		index, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("Index could is not an integer! %s", err)
		}
		outputMatrix[index/m][index%m] = true
	}
	return outputMatrix, nil
}

func BoolArrayToImage(inputMatrix [][]bool, bounds image.Rectangle) image.Image {
	input_img := image.NewRGBA(bounds)
	blocksizeX := input_img.Rect.Max.X / len(inputMatrix)
	blocksizeY := input_img.Rect.Max.Y / len(inputMatrix[0])
	for i := 0; i < len(inputMatrix); i++ {
		for j := 0; j < len(inputMatrix[i]); j++ {
			if inputMatrix[i][j] {
				draw.Draw(input_img, image.Rect(i*blocksizeX, j*blocksizeY, (i+1)*blocksizeX, (j+1)*blocksizeY), image.Black, image.ZP, draw.Src)
			}
		}
	}
	return input_img
}

//ArgDiffArray returns the indexes where arr_1 and arr_2 mismatch.
//arr_1 and arr_2 have to be of the same size.
func ArgDiffArray(arr_1 *PartitionedData, arr_2 *PartitionedData) (map[int]bool, error) {
	ret := make(map[int]bool, 0)
	if len(*arr_1) != len(*arr_2) {
		return nil, fmt.Errorf("Array size does not match!")
	}
	for i := range *arr_1 {
		if bytes.Compare((*arr_1)[i], (*arr_2)[i]) != 0 {
			ret[i] = true
		}
	}
	return ret, nil
}
