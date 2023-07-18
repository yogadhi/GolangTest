package main

import (
	gf "GolangTest/Functions"
	"encoding/hex"
	"fmt"
	"time"
)

func main() {
	logger, err := gf.InitializeLog("app.log")
	if err != nil {
		fmt.Println(err)
		return
	}

	date := time.Now()
	maxLength := 16
	data := gf.GenerateRandomStringWithDate(date, maxLength)
	logger.Log("Random string : " + data)

	barcodeWidth := 200
	barcodeHeight := 75
	barcodeFilename := "barcode.png"
	qrCodeFilename := "qrcode.png"

	err = gf.GenerateBarcode(data, barcodeFilename, barcodeWidth, barcodeHeight)
	if err != nil {
		logger.Log(err.Error())
	}

	err = gf.GenerateQRCode(data, qrCodeFilename)
	if err != nil {
		logger.Log(err.Error())
	}

	registryKey := "GeneratedPassword"
	encryptionkey, err := gf.GenerateEncryptionKey()
	if err != nil {
		logger.Log("Error generating encryption key : " + err.Error())
		return
	}

	keyString := hex.EncodeToString(encryptionkey)
	logger.Log("Generated Encryption Key : " + keyString)

	plainText := gf.GeneratePassword(12)
	logger.Log("Plain Text : " + plainText)

	encrypted, err := gf.Encrypt([]byte(plainText), encryptionkey)
	if err != nil {
		logger.Log("Encryption error : " + err.Error())
		return
	}
	logger.Log("Encrypted Text : " + encrypted)

	err = gf.SaveToRegistry(registryKey, encrypted)
	if err != nil {
		logger.Log("Error saving value to the registry : " + err.Error())
		return
	}

	value, errx := gf.GetFromRegistry(registryKey)
	if errx != nil {
		logger.Log("Error getting value from the registry : " + errx.Error())
		return
	}
	logger.Log("Value retrieved from the registry : " + value)

	decrypted, err := gf.Decrypt(value, encryptionkey)
	if err != nil {
		logger.Log("Decryption error : " + err.Error())
		return
	}
	logger.Log("Decrypted Text : " + decrypted)

	// err = gf.DeleteRegistryValue(registryKey)
	// if err != nil {
	// 	fmt.Println("Error deleting registry value:", err)
	// 	return
	// }
	// fmt.Println("Registry value deleted successfully.")
}
