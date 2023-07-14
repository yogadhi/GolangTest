package globalfunction

import (
	"bytes"
	"compress/flate"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/oned"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
)

const (
	// Barcode parameters
	barWidth  = 4
	barHeight = 200
	textSize  = 20
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	// Mapping of characters to barcode pattern
	characters = map[rune]string{
		'0': "0001101",
		'1': "0011001",
		'2': "0010011",
		'3': "0111101",
		'4': "0100011",
		'5': "0110001",
		'6': "0101111",
		'7': "0111011",
		'8': "0110111",
		'9': "0001011",
	}

	// Barcode encoding start and end markers
	startMarker = "101"
	endMarker   = "101"
)

func CompressBytes(input []byte) ([]byte, error) {
	var b bytes.Buffer

	// Create a flate writer with the best compression level
	compressor, err := flate.NewWriter(&b, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	defer compressor.Close()

	// Write the input data to the compressor
	_, err = compressor.Write(input)
	if err != nil {
		return nil, err
	}

	// Flush the compressor to ensure all data is written
	err = compressor.Flush()
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func GenerateRandomStringWithDate(date time.Time, maxLength int) string {
	dateStr := date.Format("20060102") // Format date as YYYYMMDD

	remainingLength := maxLength - len(dateStr)
	if remainingLength <= 0 {
		return strings.ToUpper(dateStr)
	}

	rand.Seed(time.Now().UnixNano())

	b := make([]byte, remainingLength)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	randomString := fmt.Sprintf("%s%s", dateStr, string(b))
	return strings.ToUpper(randomString)
}

func GenerateBarcode(data string, filename string, width, height int) error {
	// data that will be encoded into our barcode
	// Generate a new writer for Code 128 barcode
	// this format allows you to encode all ASCII characters!
	writer := oned.NewCode128Writer()
	// with the writer, we can start encoding!
	img, err := writer.Encode(data, gozxing.BarcodeFormat_CODE_128, width, height, nil)
	if err != nil {
		return err
	}
	// create a file that will hold our barcode
	file, err := os.Create("barcode.png")
	if err != nil {
		return err
	}
	defer file.Close()
	// Encode the image in PNG
	err = png.Encode(file, img)
	if err != nil {
		return err
	}
	fmt.Println("Barcode generated and saved to: " + filename)
	return nil
}

func GenerateBarcodeCustom(data string, filename string) error {
	// Prepare the barcode image dimensions
	width := (len(data) * barWidth * 7) + (len(startMarker) + len(endMarker) + 12)
	height := barHeight + textSize

	// Create a new image with the specified dimensions
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Set the background color
	backgroundColor := color.White
	for x := 0; x < width; x++ {
		for y := 0; y < height; y++ {
			img.Set(x, y, backgroundColor)
		}
	}

	// Draw the barcode pattern
	drawX := 0
	for _, char := range startMarker {
		drawX += DrawBarcodeChar(img, drawX, char)
	}

	for _, char := range data {
		drawX += DrawBarcodeChar(img, drawX, char)
	}

	for _, char := range endMarker {
		drawX += DrawBarcodeChar(img, drawX, char)
	}

	// Save the image to a file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	err = png.Encode(file, img)
	if err != nil {
		return err
	}

	fmt.Printf("Barcode generated and saved to: %s\n", filename)
	return nil
}

func DrawBarcodeChar(img *image.RGBA, x int, char rune) int {
	pattern, exists := characters[char]
	if !exists {
		return 0
	}

	drawX := x
	drawY := 0

	// Draw the barcode pattern
	for _, digit := range pattern {
		if digit == '1' {
			for i := 0; i < barHeight; i++ {
				img.Set(drawX, drawY+i, color.Black)
			}
		}

		drawX++
	}

	return len(pattern)
}

func GenerateQRCode(data string, filename string) error {
	// Create a new QR code with the specified data and correction level
	qrCode, err := qr.Encode(data, qr.L, qr.Auto)
	if err != nil {
		return err
	}

	// Scale the QR code to the desired width and height
	qrCode, err = barcode.Scale(qrCode, 200, 200)
	if err != nil {
		return err
	}

	// Create a new file to save the QR code image
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Encode the QR code as PNG and save it to the file
	err = png.Encode(file, qrCode)
	if err != nil {
		return err
	}

	fmt.Printf("QR code generated and saved to: %s\n", filename)
	return nil
}

func FindUnique(arr1, arr2 []string) []string {
	// Create a map to track the occurrences of elements
	occurrences := make(map[string]bool)

	// Iterate over the first array and mark elements as present
	for _, str := range arr1 {
		occurrences[str] = true
	}

	// Iterate over the second array and mark elements as absent
	for _, str := range arr2 {
		delete(occurrences, str)
	}

	// Create a new slice for the unique elements
	unique := make([]string, 0, len(occurrences))

	// Add the remaining elements from the map to the unique slice
	for str := range occurrences {
		unique = append(unique, str)
	}

	return unique
}

func AttachBarcodeToPDF(inputPDF string, barcodeImage string, outputPDF string) error {
	// Read the input PDF file
	pdfContent, err := ioutil.ReadFile(inputPDF)
	if err != nil {
		return err
	}

	// Create a new PDF context from the input PDF
	ctx, err := pdfcpu.Read(pdfContent, pdfcpu.NewDefaultConfiguration())
	if err != nil {
		return err
	}

	// Read the barcode image
	barcodeContent, err := ioutil.ReadFile(barcodeImage)
	if err != nil {
		return err
	}

	// Add a new page to the PDF for the barcode
	ctx.AddPage()
	pageCount := len(ctx.PageList)

	// Add the barcode image to the new page
	err = ctx.AddImageFromBytes(barcodeContent, pdfcpu.ImageHandlingSkip, pageCount, nil)
	if err != nil {
		return err
	}

	// Write the modified PDF to the output file
	err = api.WritePDFFile(ctx, outputPDF)
	if err != nil {
		return err
	}

	fmt.Printf("Barcode attached to PDF and saved to: %s\n", outputPDF)
	return nil
}
