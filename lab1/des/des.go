package des

// package main

import (
	"errors"
	"fmt"
	"lab1/feistel"
	"lab1/permutations"
)

const DESBlockSize = 8
const DESKeySize = 8
const DESRounds = 16

var IPTable = []int{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
}

var FPTable = []int{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
}

var ExpansionTable = []int{
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1,
}

var PermutationTable = []int{
	16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25,
}

var SBoxes = [8][4][16]byte{
	{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	},
	{
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	},
	{
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	},
	{
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	},
	{
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	},
	{
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	},
	{
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	},
	{
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
	},
}

var PC1Table = []int{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
}

var PC2Table = []int{
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
}

var RotationSchedule = []int{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

func extract6Bits(data []byte, startBit int) byte {
	var result byte = 0
	for i := 0; i < 6; i++ {
		bitIndex := startBit + i
		byteIndex := bitIndex / 8
		bitPos := 7 - (bitIndex % 8)
		bit := (data[byteIndex] >> bitPos) & 1
		result = (result << 1) | bit
	}
	return result
}

func set4Bits(data []byte, position int, value byte) {
	for i := 0; i < 4; i++ {
		bitIdx := position*4 + i
		byteIdx := bitIdx / 8
		bitPos := 7 - (bitIdx % 8)

		if (value & (1 << (3 - i))) != 0 {
			data[byteIdx] |= (1 << bitPos)
		} else {
			data[byteIdx] &^= (1 << bitPos)
		}
	}
}

func extractBits(data []byte, start, n int) []byte {
	result := make([]byte, (n+7)/8)
	for i := 0; i < n; i++ {
		srcBit := start + i
		srcByte := srcBit / 8
		srcPos := 7 - (srcBit % 8)

		dstByte := i / 8
		dstPos := 7 - (i % 8)

		if srcByte < len(data) {
			if (data[srcByte]>>srcPos)&1 != 0 {
				result[dstByte] |= 1 << dstPos
			}
		}
	}
	return result
}

func rotateLeft28(data []byte, shift int) []byte {
	result := make([]byte, len(data))
	for i := 0; i < 28; i++ {
		srcBit := (i + shift) % 28
		srcByte := srcBit / 8
		srcPos := 7 - (srcBit % 8)

		dstByte := i / 8
		dstPos := 7 - (i % 8)

		if (data[srcByte]>>srcPos)&1 != 0 {
			result[dstByte] |= 1 << dstPos
		}
	}
	return result
}

func combineBits(a, b []byte, bitsPerPart int) []byte {
	totalBits := bitsPerPart * 2
	result := make([]byte, (totalBits+7)/8)

	for i := 0; i < bitsPerPart; i++ {
		srcByte := i / 8
		srcPos := 7 - (i % 8)

		dstByte := i / 8
		dstPos := 7 - (i % 8)

		if (a[srcByte]>>srcPos)&1 != 0 {
			result[dstByte] |= 1 << dstPos
		}
	}

	for i := 0; i < bitsPerPart; i++ {
		srcByte := i / 8
		srcPos := 7 - (i % 8)

		dstBit := bitsPerPart + i
		dstByte := dstBit / 8
		dstPos := 7 - (dstBit % 8)

		if (b[srcByte]>>srcPos)&1 != 0 {
			result[dstByte] |= 1 << dstPos
		}
	}

	return result
}

type DESFFunction struct{}

func NewDESFFunction() *DESFFunction {
	return &DESFFunction{}
}

func (df *DESFFunction) Apply(rightHalf []byte, roundKey []byte) ([]byte, error) {
	if len(rightHalf) != 4 {
		return nil, errors.New("DES right half must be 4 bytes")
	}
	if len(roundKey) != 6 {
		return nil, errors.New("DES round key must be 6 bytes")
	}

	expanded, err := permutations.BitPermutations(rightHalf, ExpansionTable, permutations.HighToLow, permutations.FirstBit)
	if err != nil {
		return nil, fmt.Errorf("expansion failed: %w", err)
	}

	for i := 0; i < len(expanded) && i < len(roundKey); i++ {
		expanded[i] ^= roundKey[i]
	}

	substituted := make([]byte, 4)
	for i := 0; i < 8; i++ {
		sixBits := extract6Bits(expanded, i*6)
		row := ((sixBits & 0x20) >> 4) | (sixBits & 0x01)
		col := (sixBits & 0x1E) >> 1

		value := SBoxes[i][row][col]
		set4Bits(substituted, i, value)
	}

	result, err := permutations.BitPermutations(substituted, PermutationTable, permutations.HighToLow, permutations.FirstBit)
	if err != nil {
		return nil, fmt.Errorf("permutation failed: %w", err)
	}

	return result, nil
}

func (df *DESFFunction) HalfBlockSize() int {
	return 4
}

type DESKeySchedule struct{}

func NewDESKeySchedule() *DESKeySchedule {
	return &DESKeySchedule{}
}

func (dks *DESKeySchedule) ExpandKey(key []byte) ([][]byte, error) {
	if len(key) != DESKeySize {
		return nil, fmt.Errorf("DES key must be %d bytes", DESKeySize)
	}

	permutedKey, err := permutations.BitPermutations(key, PC1Table, permutations.HighToLow, permutations.FirstBit)
	if err != nil {
		return nil, fmt.Errorf("PC1 failed: %w", err)
	}

	C := extractBits(permutedKey, 0, 28)
	D := extractBits(permutedKey, 28, 28)

	roundKeys := make([][]byte, DESRounds)

	for i := 0; i < DESRounds; i++ {
		C = rotateLeft28(C, RotationSchedule[i])
		D = rotateLeft28(D, RotationSchedule[i])

		combined := combineBits(C, D, 28)

		roundKey, err := permutations.BitPermutations(combined, PC2Table, permutations.HighToLow, permutations.FirstBit)
		if err != nil {
			return nil, fmt.Errorf("PC2 failed at round %d: %w", i, err)
		}

		roundKeys[i] = roundKey
	}

	return roundKeys, nil
}

func (dks *DESKeySchedule) NumRounds() int {
	return DESRounds
}

type DES struct {
	network *feistel.FeistelNetwork
}

func NewDES() (*DES, error) {
	fFunc := NewDESFFunction()
	keySchedule := NewDESKeySchedule()

	network, err := feistel.NewFeistelNetwork(fFunc, keySchedule)
	if err != nil {
		return nil, err
	}

	return &DES{network: network}, nil
}

func (d *DES) SetKey(key []byte) error {
	return d.network.SetKey(key)
}

func (d *DES) Encrypt(block []byte) ([]byte, error) {
	if len(block) != DESBlockSize {
		return nil, fmt.Errorf("DES block must be %d bytes", DESBlockSize)
	}

	permuted, err := permutations.BitPermutations(block, IPTable, permutations.HighToLow, permutations.FirstBit)
	if err != nil {
		return nil, fmt.Errorf("IP failed: %w", err)
	}

	result, err := d.network.Encrypt(permuted)
	if err != nil {
		return nil, fmt.Errorf("feistel encrypt failed: %w", err)
	}

	if len(result) != DESBlockSize {
		return nil, errors.New("unexpected block size after encryption rounds")
	}
	swapped := make([]byte, DESBlockSize)
	copy(swapped[:4], result[4:])
	copy(swapped[4:], result[:4])

	final, err := permutations.BitPermutations(swapped, FPTable, permutations.HighToLow, permutations.FirstBit)
	if err != nil {
		return nil, fmt.Errorf("FP failed: %w", err)
	}

	return final, nil
}

func (d *DES) Decrypt(block []byte) ([]byte, error) {
	if len(block) != DESBlockSize {
		return nil, fmt.Errorf("DES block must be %d bytes", DESBlockSize)
	}

	permuted, err := permutations.BitPermutations(block, IPTable, permutations.HighToLow, permutations.FirstBit)
	if err != nil {
		return nil, fmt.Errorf("IP failed: %w", err)
	}

	if len(permuted) != DESBlockSize {
		return nil, errors.New("unexpected block size after initial permutation")
	}
	swapped := make([]byte, DESBlockSize)
	copy(swapped[:4], permuted[4:])
	copy(swapped[4:], permuted[:4])
	result, err := d.network.Decrypt(swapped)
	if err != nil {
		return nil, fmt.Errorf("feistel decrypt failed: %w", err)
	}

	final, err := permutations.BitPermutations(result, FPTable, permutations.HighToLow, permutations.FirstBit)
	if err != nil {
		return nil, fmt.Errorf("FP failed: %w", err)
	}

	return final, nil
}

func (d *DES) BlockSize() int {
	return DESBlockSize
}

/*func main() {
	desCipher, err := NewDES()
	if err != nil {
		panic(err)
	}

	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	fmt.Printf("Key:\t\t% x\n", key)

	err = desCipher.SetKey(key)
	if err != nil {
		panic(err)
	}

	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	fmt.Printf("Plaintext:\t% x\n", plaintext)

	encrypted, err := desCipher.Encrypt(plaintext)
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		return
	}
	fmt.Printf("Encrypted:\t% x\n", encrypted)

	decrypted, err := desCipher.Decrypt(encrypted)
	if err != nil {
		fmt.Printf("Decryption error:\t%v\n", err)
		return
	}
	fmt.Printf("Decrypted:\t% x\n", decrypted)
}*/
