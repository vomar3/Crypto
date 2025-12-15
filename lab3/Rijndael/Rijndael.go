package Rijndael

import (
	"fmt"
	"lab1/interfaces"
	"lab3/statelessService"
)

const (
	BlockSize128 = 16
	BlockSize192 = 24
	BlockSize256 = 32
)

var rconTable = [15]byte{
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
	0x6C, 0xD8, 0xAB, 0x4D,
}

func computeSBoxes(gf28Service *statelessService.GF28Service, modulus byte) ([]byte, []byte) {
	sbox := make([]byte, 256)
	invSbox := make([]byte, 256)

	for i := 0; i < 256; i++ {
		var invValue byte
		if i == 0 {
			invValue = 0
		} else {
			invValue, _ = gf28Service.Inverse(byte(i), modulus)
		}
		sbox[i] = affineTransform(invValue)
	}

	for i := 0; i < 256; i++ {
		afterInvAffine := inverseAffineTransform(byte(i))
		var result byte
		if afterInvAffine == 0 {
			result = 0
		} else {
			result, _ = gf28Service.Inverse(afterInvAffine, modulus)
		}
		invSbox[i] = result
	}

	return sbox, invSbox
}

func bytesToState(data []byte, nb int) [][]byte {
	state := make([][]byte, 4)
	for i := range state {
		state[i] = make([]byte, nb)
	}

	for col := 0; col < nb; col++ {
		for row := 0; row < 4; row++ {
			state[row][col] = data[row+col*4]
		}
	}

	return state
}

func stateToBytes(state [][]byte) []byte {
	nb := len(state[0])
	result := make([]byte, 4*nb)

	for col := 0; col < nb; col++ {
		for row := 0; row < 4; row++ {
			result[row+col*4] = state[row][col]
		}
	}

	return result
}

func addRoundKey(state [][]byte, roundKey []byte) {
	nb := len(state[0])
	for col := 0; col < nb; col++ {
		for row := 0; row < 4; row++ {
			state[row][col] ^= roundKey[row+col*4]
		}
	}
}

type RijndaelKeyExpander struct {
	blockSize   int
	keySize     int
	modulus     byte
	gf28Service *statelessService.GF28Service
	numRounds   int
	sbox        []byte
}

func NewRijndaelKeyExpander(blockSize, keySize int, modulus byte, sbox []byte) (*RijndaelKeyExpander, error) {
	if blockSize != BlockSize128 && blockSize != BlockSize192 && blockSize != BlockSize256 {
		return nil, fmt.Errorf("NewRijndaelKeyExpander: invalid block size")
	}

	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("NewRijndaelKeyExpander: invalid key size")
	}

	gf28Service := statelessService.NewGF28Service()
	if gf28Service == nil {
		return nil, fmt.Errorf("NewRijndaelKeyExpander: failed to create GF28Service")
	}

	isIrreducible, err := gf28Service.IsIrreducibleDegree8(uint16(modulus) | 0x100)
	if err != nil {
		return nil, err
	}
	if !isIrreducible {
		return nil, fmt.Errorf("NewRijndaelKeyExpander: modulus not irreducible")
	}

	numRounds := calculateNumRounds(blockSize, keySize)

	return &RijndaelKeyExpander{
		blockSize:   blockSize,
		keySize:     keySize,
		modulus:     modulus,
		gf28Service: gf28Service,
		numRounds:   numRounds,
		sbox:        sbox,
	}, nil
}

func (rke *RijndaelKeyExpander) ExpandKey(key []byte) ([][]byte, error) {
	if len(key) != rke.keySize {
		return nil, fmt.Errorf("ExpandKey: invalid key size")
	}

	nk := rke.keySize / 4
	nb := rke.blockSize / 4
	totalWords := nb * (rke.numRounds + 1)

	w := make([][]byte, totalWords)

	for i := 0; i < nk; i++ {
		w[i] = make([]byte, 4)
		copy(w[i], key[i*4:(i+1)*4])
	}

	for i := nk; i < totalWords; i++ {
		temp := make([]byte, 4)
		copy(temp, w[i-1])

		if i%nk == 0 {
			temp = []byte{temp[1], temp[2], temp[3], temp[0]}

			for j := 0; j < 4; j++ {
				temp[j] = rke.sbox[temp[j]]
			}

			temp[0] ^= rconTable[i/nk]

		} else if nk > 6 && i%nk == 4 {
			for j := 0; j < 4; j++ {
				temp[j] = rke.sbox[temp[j]]
			}
		}

		w[i] = make([]byte, 4)
		for j := 0; j < 4; j++ {
			w[i][j] = w[i-nk][j] ^ temp[j]
		}
	}

	roundKeys := make([][]byte, rke.numRounds+1)
	for round := 0; round <= rke.numRounds; round++ {
		roundKeys[round] = make([]byte, rke.blockSize)
		for i := 0; i < nb; i++ {
			copy(roundKeys[round][i*4:(i+1)*4], w[round*nb+i])
		}
	}

	return roundKeys, nil
}

type RijndaelRoundTransformer struct {
	blockSize   int
	modulus     byte
	gf28Service *statelessService.GF28Service
	sbox        []byte
	invSbox     []byte
}

func NewRijndaelRoundTransformer(blockSize int, modulus byte, sbox, invSbox []byte) (*RijndaelRoundTransformer, error) {
	if blockSize != BlockSize128 && blockSize != BlockSize192 && blockSize != BlockSize256 {
		return nil, fmt.Errorf("NewRijndaelRoundTransformer: invalid block size")
	}

	gf28Service := statelessService.NewGF28Service()
	if gf28Service == nil {
		return nil, fmt.Errorf("NewRijndaelRoundTransformer: failed to create service")
	}

	isIrreducible, _ := gf28Service.IsIrreducibleDegree8(uint16(modulus) | 0x100)
	if !isIrreducible {
		return nil, fmt.Errorf("NewRijndaelRoundTransformer: modulus not irreducible")
	}

	return &RijndaelRoundTransformer{
		blockSize:   blockSize,
		modulus:     modulus,
		gf28Service: gf28Service,
		sbox:        sbox,
		invSbox:     invSbox,
	}, nil
}

func (rrt *RijndaelRoundTransformer) Transform(inputBlock []byte, roundKey []byte) ([]byte, error) {
	if len(inputBlock) != rrt.blockSize {
		return nil, fmt.Errorf("Transform: invalid block size")
	}

	nb := rrt.blockSize / 4
	state := bytesToState(inputBlock, nb)
	rrt.subBytes(state, false)
	shiftRows(state, false)
	rrt.mixColumns(state, false)
	addRoundKey(state, roundKey)

	return stateToBytes(state), nil
}

func (rrt *RijndaelRoundTransformer) subBytes(state [][]byte, inverse bool) {
	nb := len(state[0])
	box := rrt.sbox
	if inverse {
		box = rrt.invSbox
	}

	for row := 0; row < 4; row++ {
		for col := 0; col < nb; col++ {
			state[row][col] = box[state[row][col]]
		}
	}
}

func (rrt *RijndaelRoundTransformer) mixColumns(state [][]byte, inverse bool) {
	nb := len(state[0])
	for col := 0; col < nb; col++ {
		temp := []byte{state[0][col], state[1][col], state[2][col], state[3][col]}
		if inverse {
			state[0][col], state[1][col], state[2][col], state[3][col], _ = rrt.invMixColumn(temp)
		} else {
			state[0][col], state[1][col], state[2][col], state[3][col], _ = rrt.mixColumn(temp)
		}
	}
}

func (rrt *RijndaelRoundTransformer) mulColumn(coef byte, col []byte) []byte {
	result := make([]byte, 4)
	for i := 0; i < 4; i++ {
		result[i], _ = rrt.gf28Service.Multiply(coef, col[i], rrt.modulus)
	}
	return result
}

func (rrt *RijndaelRoundTransformer) mixColumn(col []byte) (byte, byte, byte, byte, error) {
	mul2 := rrt.mulColumn(0x02, col)
	mul3 := rrt.mulColumn(0x03, col)

	r0 := mul2[0] ^ mul3[1] ^ col[2] ^ col[3]
	r1 := col[0] ^ mul2[1] ^ mul3[2] ^ col[3]
	r2 := col[0] ^ col[1] ^ mul2[2] ^ mul3[3]
	r3 := mul3[0] ^ col[1] ^ col[2] ^ mul2[3]

	return r0, r1, r2, r3, nil
}

func (rrt *RijndaelRoundTransformer) invMixColumn(col []byte) (byte, byte, byte, byte, error) {
	mul9 := rrt.mulColumn(0x09, col)
	mul11 := rrt.mulColumn(0x0B, col)
	mul13 := rrt.mulColumn(0x0D, col)
	mul14 := rrt.mulColumn(0x0E, col)

	r0 := mul14[0] ^ mul11[1] ^ mul13[2] ^ mul9[3]
	r1 := mul9[0] ^ mul14[1] ^ mul11[2] ^ mul13[3]
	r2 := mul13[0] ^ mul9[1] ^ mul14[2] ^ mul11[3]
	r3 := mul11[0] ^ mul13[1] ^ mul9[2] ^ mul14[3]

	return r0, r1, r2, r3, nil
}

type RijndaelCipher struct {
	blockSize           int
	keyExpander         interfaces.KeyExpander
	transformer         interfaces.RoundTransformer
	roundKeys           [][]byte
	numRounds           int
	concreteTransformer *RijndaelRoundTransformer
}

func NewRijndaelCipher(blockSize, keySize int, modulus byte) (*RijndaelCipher, error) {
	if blockSize != BlockSize128 && blockSize != BlockSize192 && blockSize != BlockSize256 {
		return nil, fmt.Errorf("NewRijndaelCipher: invalid block size")
	}

	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("NewRijndaelCipher: invalid key size")
	}

	gf28Service := statelessService.NewGF28Service()
	if gf28Service == nil {
		return nil, fmt.Errorf("NewRijndaelCipher: failed to create GF28Service")
	}

	sbox, invSbox := computeSBoxes(gf28Service, modulus)

	keyExpander, err := NewRijndaelKeyExpander(blockSize, keySize, modulus, sbox)
	if err != nil {
		return nil, err
	}

	transformer, err := NewRijndaelRoundTransformer(blockSize, modulus, sbox, invSbox)
	if err != nil {
		return nil, err
	}

	numRounds := calculateNumRounds(blockSize, keySize)

	return &RijndaelCipher{
		blockSize:           blockSize,
		keyExpander:         keyExpander,
		transformer:         transformer,
		concreteTransformer: transformer,
		numRounds:           numRounds,
	}, nil
}

func (rc *RijndaelCipher) SetKey(key []byte) error {
	if rc.keyExpander == nil {
		return fmt.Errorf("SetKey: keyExpander is nil")
	}

	roundKeys, err := rc.keyExpander.ExpandKey(key)
	if err != nil {
		return err
	}

	rc.roundKeys = roundKeys
	return nil
}

func (rc *RijndaelCipher) BlockSize() int {
	return rc.blockSize
}

func (rc *RijndaelCipher) Encrypt(block []byte) ([]byte, error) {
	if len(block) != rc.blockSize {
		return nil, fmt.Errorf("Encrypt: invalid block size")
	}

	if rc.roundKeys == nil {
		return nil, fmt.Errorf("Encrypt: key not set")
	}

	nb := rc.blockSize / 4

	result := make([]byte, rc.blockSize)
	copy(result, block)
	for i := 0; i < len(result) && i < len(rc.roundKeys[0]); i++ {
		result[i] ^= rc.roundKeys[0][i]
	}

	for round := 1; round < rc.numRounds; round++ {
		var err error
		result, err = rc.transformer.Transform(result, rc.roundKeys[round])
		if err != nil {
			return nil, err
		}
	}

	state := bytesToState(result, nb)
	rc.concreteTransformer.subBytes(state, false)
	shiftRows(state, false)
	addRoundKey(state, rc.roundKeys[rc.numRounds])

	return stateToBytes(state), nil
}

func (rc *RijndaelCipher) Decrypt(block []byte) ([]byte, error) {
	if len(block) != rc.blockSize {
		return nil, fmt.Errorf("Decrypt: invalid block size")
	}

	if rc.roundKeys == nil {
		return nil, fmt.Errorf("Decrypt: key not set")
	}

	nb := rc.blockSize / 4
	state := bytesToState(block, nb)

	addRoundKey(state, rc.roundKeys[rc.numRounds])

	for round := rc.numRounds - 1; round >= 1; round-- {
		shiftRows(state, true)
		rc.concreteTransformer.subBytes(state, true)
		addRoundKey(state, rc.roundKeys[round])
		rc.concreteTransformer.mixColumns(state, true)
	}

	shiftRows(state, true)
	rc.concreteTransformer.subBytes(state, true)
	addRoundKey(state, rc.roundKeys[0])

	return stateToBytes(state), nil
}

func calculateNumRounds(blockSize, keySize int) int {
	nb := blockSize / 4
	nk := keySize / 4
	if nb > nk {
		return nb + 6
	}
	return nk + 6
}

func affineTransform(b byte) byte {
	result := byte(0x63)
	for i := 0; i < 8; i++ {
		bit := ((b >> i) & 1) ^ ((b >> ((i + 4) % 8)) & 1) ^ ((b >> ((i + 5) % 8)) & 1) ^
			((b >> ((i + 6) % 8)) & 1) ^ ((b >> ((i + 7) % 8)) & 1)
		result ^= (bit << i)
	}
	return result
}

func inverseAffineTransform(b byte) byte {
	result := byte(0)
	for i := 0; i < 8; i++ {
		bit := ((b >> ((i + 2) % 8)) & 1) ^ ((b >> ((i + 5) % 8)) & 1) ^ ((b >> ((i + 7) % 8)) & 1)
		result ^= (bit << i)
	}
	return result ^ 0x05
}

func shiftRows(state [][]byte, inverse bool) {
	nb := len(state[0])

	var shifts [4]int
	if nb == 4 || nb == 6 {
		shifts = [4]int{0, 1, 2, 3}
	} else {
		shifts = [4]int{0, 1, 3, 4}
	}

	temp := make([]byte, nb)

	for row := 1; row < 4; row++ {
		copy(temp, state[row])

		shift := shifts[row]
		if inverse {
			shift = nb - shift
		}

		for col := 0; col < nb; col++ {
			state[row][col] = temp[(col+shift)%nb]
		}
	}
}
