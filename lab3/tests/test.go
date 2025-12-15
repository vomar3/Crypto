package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"lab1/interfaces"
	"lab3/Rijndael"
	"os"
	"path/filepath"
)

func testFile(cipher interfaces.BlockCipher, filePath, mode string, key []byte) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	padding := interfaces.PKCS7
	if mode == "CTR" || mode == "CFB" || mode == "OFB" {
		padding = interfaces.Zeros
	}

	config := interfaces.CipherContextConfig{
		Key:     key,
		Mode:    getModeFromString(mode),
		Padding: padding,
	}

	cc, err := interfaces.NewCipherContext(cipher, config)
	if err != nil {
		return err
	}

	ctx := context.Background()

	encrypted, err := cc.EncryptBytes(ctx, data)
	if err != nil {
		return err
	}

	decrypted, err := cc.DecryptBytes(ctx, encrypted)
	if err != nil {
		return err
	}

	match := len(data) == len(decrypted)
	if match {
		for i := range data {
			if data[i] != decrypted[i] {
				match = false
				break
			}
		}
	}

	fmt.Printf("%s: %d -> %d bytes [%v]\n", mode, len(data), len(encrypted), match)
	return nil
}

func getModeFromString(mode string) interfaces.CipherMode {
	switch mode {
	case "ECB":
		return interfaces.ECB
	case "CBC":
		return interfaces.CBC
	case "CTR":
		return interfaces.CTR
	case "CFB":
		return interfaces.CFB
	case "OFB":
		return interfaces.OFB
	case "PCBC":
		return interfaces.PCBC
	default:
		return interfaces.ECB
	}
}

func testCipherWithKey(cipher interfaces.BlockCipher, key []byte, keyName string) {
	testFolder := "test_data"
	files, err := os.ReadDir(testFolder)
	if err != nil {
		fmt.Printf("Error reading folder: %v\n", err)
		return
	}

	modes := []string{"ECB", "CBC", "PCBC", "CTR", "CFB", "OFB"}

	fmt.Printf("\n=== %s ===\n", keyName)

	for _, file := range files {
		filePath := filepath.Join(testFolder, file.Name())
		fileInfo, _ := file.Info()

		fmt.Printf("\n%s (%d bytes):\n", file.Name(), fileInfo.Size())
		for _, mode := range modes {
			err := testFile(cipher, filePath, mode, key)
			if err != nil {
				fmt.Printf("%-12s: error - %v\n", mode, err)
			}
		}
	}

	fmt.Println("\nPseudorandom sequences")
	sizes := []int{16, 64, 256, 1024}
	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)
		fmt.Printf("%d bytes: \n", size)
		for _, mode := range modes {
			padding := interfaces.PKCS7

			if mode == "CTR" || mode == "CFB" || mode == "OFB" {
				padding = interfaces.Zeros
			}

			config := interfaces.CipherContextConfig{
				Key:     key,
				Mode:    getModeFromString(mode),
				Padding: padding,
			}

			cc, _ := interfaces.NewCipherContext(cipher, config)
			ctx := context.Background()
			encrypted, _ := cc.EncryptBytes(ctx, data)
			decrypted, _ := cc.DecryptBytes(ctx, encrypted)

			match := len(data) == len(decrypted)
			if match {
				for i := range data {
					if data[i] != decrypted[i] {
						match = false
						break
					}
				}
			}

			fmt.Printf("%s: %v\n", mode, match)
		}

		fmt.Println()
	}
}

func main() {
	cipher128, err := Rijndael.NewRijndaelCipher(Rijndael.BlockSize128, 16, 0x1B)
	if err != nil {
		fmt.Printf("Error creating AES-128: %v\n", err)
		return
	}
	key128 := []byte("AESKey128Bit!!!!")
	testCipherWithKey(cipher128, key128, "AES-128 (128-bit key)")

	cipher192, err := Rijndael.NewRijndaelCipher(Rijndael.BlockSize128, 24, 0x1B)
	if err != nil {
		fmt.Printf("Error creating AES-192: %v\n", err)
		return
	}
	key192 := []byte("AESKey192Bit!!!!!!!!!!!!")
	testCipherWithKey(cipher192, key192, "AES-192 (192-bit key)")

	cipher256, err := Rijndael.NewRijndaelCipher(Rijndael.BlockSize128, 32, 0x1B)
	if err != nil {
		fmt.Printf("Error creating AES-256: %v\n", err)
		return
	}
	key256 := []byte("AESKey256Bit!!!!!!!!!!!!!!!!!!!!")
	testCipherWithKey(cipher256, key256, "AES-256 (256-bit key)")
}
