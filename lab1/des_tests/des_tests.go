package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"lab1/des"
	"lab1/interfaces"
	"os"
	"path/filepath"
)

func testFile(cipher interfaces.BlockCipher, filePath, mode string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	padding := interfaces.PKCS7
	if mode == "CTR" || mode == "CFB" || mode == "OFB" {
		padding = interfaces.Zeros
	}

	config := interfaces.CipherContextConfig{
		Key:     []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
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

func main() {
	desCipher, _ := des.NewDES()
	var cipher interfaces.BlockCipher = desCipher

	testFolder := "test_data"
	files, err := os.ReadDir(testFolder)
	if err != nil {
		fmt.Printf("Error reading folder: %v\n", err)
		return
	}

	modes := []string{"ECB", "CBC", "CTR", "CFB", "OFB"}

	for _, file := range files {
		filePath := filepath.Join(testFolder, file.Name())
		fileInfo, _ := file.Info()

		fmt.Printf("\n%s (%d bytes):\n", file.Name(), fileInfo.Size())
		for _, mode := range modes {
			err := testFile(cipher, filePath, mode)
			if err != nil {
				fmt.Printf("%-4s: error - %v\n", mode, err)
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
				Key:     []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
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
