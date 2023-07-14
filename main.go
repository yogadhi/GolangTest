package main

import (
	gf "GolangTest/Functions"
	"log"
	"time"
)

func main() {
	date := time.Now()
	maxLength := 16
	data := gf.GenerateRandomStringWithDate(date, maxLength)
	data = "P33333"
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

}
