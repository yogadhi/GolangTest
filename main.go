package main

import (
	gf "GolangTest/Functions"
	"encoding/hex"
	"fmt"
	"log"
	"time"
)

func main() {
	date := time.Now()
	maxLength := 16
	data := gf.GenerateRandomStringWithDate(date, maxLength)
	fmt.Println("Random string : " + data)

	barcodeFilename := "barcode.png"
	qrCodeFilename := "qrcode.png"

	err := gf.GenerateBarcode(data, barcodeFilename, 200, 75)
	if err != nil {
		log.Fatal(err)
	}

	err = gf.GenerateQRCode(data, qrCodeFilename)
	if err != nil {
		log.Fatal(err)
	}

	// key := []byte("01234567890123456789012345678901")

	key, err := gf.GenerateEncryptionKey()
	if err != nil {
		fmt.Println("Error generating encryption key:", err)
		return
	}

	// Convert the key to a hexadecimal string for display or storage
	keyString := hex.EncodeToString(key)
	fmt.Println("Generated Encryption Key:", keyString)

	plainText := "Hello, World!"
	fmt.Println("Plain Text:", plainText)

	encrypted, err := gf.Encrypt([]byte(plainText), key)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}

	fmt.Println("Encrypted Text:", encrypted)

	decrypted, err := gf.Decrypt(encrypted, key)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	fmt.Println("Decrypted Text:", decrypted)

	err = gf.SaveToRegistry("Hello, Registry!")
	if err != nil {
		fmt.Println("Error saving value to the registry:", err)
		return
	}

	// Get the value from the registry
	value, errx := gf.GetFromRegistry()
	if errx != nil {
		fmt.Println("Error getting value from the registry:", errx)
		return
	}

	fmt.Println("Value retrieved from the registry:", value)

}
