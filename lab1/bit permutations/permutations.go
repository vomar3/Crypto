package main

import (
	"errors"
	"fmt"
)

type IndexMode int

const (
	LowToHigh IndexMode = iota
	HighToLow
)

type InitialBit int

const (
	ZeroBit InitialBit = iota
	FirstBit
)

func BitPermutations(bytes []byte, pBlock []int, indexMode IndexMode, initialBit InitialBit) ([]byte, error) {
	if len(bytes) == 0 {
		return nil, errors.New("The array is empty")
	}

	if len(pBlock) == 0 {
		return nil, errors.New("The problem with the p-block")
	}

	if indexMode != LowToHigh && indexMode != HighToLow {
		return nil, errors.New("Unknown indexing")
	}

	if initialBit != ZeroBit && initialBit != FirstBit {
		return nil, errors.New("Initial bit must be 0 or 1")
	}

	totalBits := len(bytes) * 8
	pBlockSize := (len(pBlock) + 7) / 8
	result := make([]byte, pBlockSize)
	totalBitsPBlock := pBlockSize * 8

	for index, bit := range pBlock {
		if initialBit == FirstBit {
			bit--
		}

		if bit < 0 || bit > totalBitsPBlock {
			return nil, fmt.Errorf("pBlock[%d] out of range", index)
		}

		bitValue := getBit(bytes, indexMode, bit, totalBits)

		setBit(result, indexMode, totalBitsPBlock, bitValue, index)
	}

	return result, nil
}

func getBit(bytes []byte, indexMode IndexMode, pBlockBit int, totalBits int) bool {
	var actualIndex int

	if indexMode == LowToHigh {
		actualIndex = totalBits - pBlockBit - 1
	} else {
		actualIndex = pBlockBit
	}

	actualByte := actualIndex / 8
	actualBit := actualIndex % 8

	return (bytes[actualByte]>>(7-actualBit))&1 == 1
}

func setBit(bytes []byte, indexMode IndexMode, totalBitsPBlock int, bitValue bool, resultIndexBit int) {
	var actualIndex int

	if indexMode == LowToHigh {
		actualIndex = totalBitsPBlock - resultIndexBit - 1
	} else {
		actualIndex = resultIndexBit
	}

	actualByte := actualIndex / 8
	actualBit := actualIndex % 8

	if bitValue {
		bytes[actualByte] |= (1 << (7 - actualBit))
	} else {
		bytes[actualByte] &^= (1 << (7 - actualBit))
	}
}

/*func main() {
	bytes := []byte{0b11001010, 0b00100110}
	pBlock := []int{10, 15, 0, 2, 5, 6, 3, 9, 11, 14, 8, 12, 13, 7, 4, 1}

	answer, err := BitPermutations(bytes, pBlock, HighToLow, ZeroBit)

	if err == nil {
		for _, value := range answer {
			fmt.Printf("%08b\n", value)
		}
	} else {
		fmt.Printf("was error: %v", err)
	}

	answer2, err2 := BitPermutations(bytes, pBlock, LowToHigh, ZeroBit)

	if err2 == nil {
		for _, value := range answer2 {
			fmt.Printf("%08b\n", value)
		}
	} else {
		fmt.Printf("was error: %v", err2)
	}

	pBlock = []int{10 + 1, 15 + 1, 0 + 1, 2 + 1, 5 + 1, 6 + 1, 3 + 1, 9 + 1, 11 + 1, 14 + 1, 8 + 1, 12 + 1, 13 + 1, 7 + 1, 4 + 1, 1 + 1}

	answer3, err3 := BitPermutations(bytes, pBlock, HighToLow, FirstBit)

	if err3 == nil {
		for _, value := range answer3 {
			fmt.Printf("%08b\n", value)
		}
	} else {
		fmt.Printf("was error: %v", err3)
	}

	answer4, err4 := BitPermutations(bytes, pBlock, LowToHigh, FirstBit)
	if err4 == nil {
		for _, value := range answer4 {
			fmt.Printf("%08b\n", value)
		}
	} else {
		fmt.Printf("was error: %v", err4)
	}
}
*/
