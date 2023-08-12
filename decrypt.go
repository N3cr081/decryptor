package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
)

func getPasswordFromWordlist(wordlistFile string) (string, error) {
	// Read the wordlist file
	wordlist, err := os.Open(wordlistFile)
	if err != nil {
		return "", err
	}
	defer wordlist.Close()

	// Create a scanner to read lines from the wordlist
	scanner := bufio.NewScanner(wordlist)

	var passwords []string

	// Read each line from the wordlist and add it to the passwords slice
	for scanner.Scan() {
		passwords = append(passwords, scanner.Text())
	}

	// Check for any errors during scanning
	if err := scanner.Err(); err != nil {
		return "", err
	}

	// Choose a random password from the wordlist
	randomIndex := rand.Intn(len(passwords))
	return passwords[randomIndex], nil
}

func removePadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}
	padding := int(data[len(data)-1])
	if padding < 1 || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:len(data)-padding], nil
}

func decryptFile(inputFile, outputFile, wordlistFile, ivHex string, keyLength int) error {
	var keySize int
	if keyLength == 128 {
		keySize = 16
	} else if keyLength == 256 {
		keySize = 32
	} else {
		return fmt.Errorf("invalid key length. Please choose either 128 or 256")
	}

	// Read the encrypted file
	encryptedData, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	// Convert IV from hexadecimal
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return err
	}

	// Get password from wordlist
	password, err := getPasswordFromWordlist(wordlistFile)
	if err != nil {
		return err
	}

	// Convert password from hexadecimal
	key, err := hex.DecodeString(password)
	if err != nil {
		return err
	}

	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(key[:keySize])
	if err != nil {
		return err
	}

	// Create a CBC mode decrypter
	decrypter := cipher.NewCBCDecrypter(block, iv)

	// Create a buffer to hold the decrypted data
	decryptedData := make([]byte, len(encryptedData))

	// Decrypt the data
	decrypter.CryptBlocks(decryptedData, encryptedData)

	// Remove padding
	decryptedData, err = removePadding(decryptedData)
	if err != nil {
		return err
	}

	// Write the decrypted data to the output file
	if err := os.WriteFile(outputFile, decryptedData, 0644); err != nil {
		return err
	}

	fmt.Println("File decrypted successfully.")
	return nil
}

func getInput(prompt string) string {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text()
}

func main() {
	var inputFile, outputFile, wordlistFile, ivHex string
	var keyLength int

	fmt.Print("Enter the path of the encrypted file: ")
	inputFile = getInput("")

	fmt.Print("Enter the path for the decrypted file: ")
	outputFile = getInput("")

	fmt.Print("Choose decryption key length (128 or 256): ")
	fmt.Scan(&keyLength)

	fmt.Print("Enter the IV in hexadecimal format: ")
	ivHex = getInput("")

	fmt.Print("Enter the path of the wordlist file: ")
	wordlistFile = getInput("")

	err := decryptFile(inputFile, outputFile, wordlistFile, ivHex, keyLength)
	if err != nil {
		fmt.Println("Error decrypting the file:", err)
		return
	}
}
