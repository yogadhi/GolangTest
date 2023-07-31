package globalfunction

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"log"
	"math/big"
	"math/rand"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/oned"
	"github.com/pquerna/otp/totp"
	"golang.org/x/sys/windows/registry"
)

const (
	//Registry Path
	keyPath = `SOFTWARE\GolangTest`

	//GenerateRandomStringWithDate
	charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	//GenerateBarcodeCustom
	barWidth  = 4
	barHeight = 200
	textSize  = 20

	//GeneratePassword
	uppercaseLetters     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowercaseLetters     = "abcdefghijklmnopqrstuvwxyz"
	digits               = "0123456789"
	specialChars         = "!@#$%^&*()-_=+,.?/:;{}[]~"
	completeSpecialChars = "!@#$%^&*()_-+={}[]|:;'<>,.?/`~"

	//TOTP
	digitCount   = 6
	timeStepSecs = 30
)

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

func GetFunctionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

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

func GenerateRandomStringWithDate(isUsingDate bool, maxLength int) string {
	str := ""

	if isUsingDate == true {
		str = time.Now().Format("20060102") // Format date as YYYYMMDD
	}

	remainingLength := maxLength - len(str)
	if remainingLength <= 0 {
		return strings.ToUpper(str)
	}

	rand.Seed(time.Now().UnixNano())

	b := make([]byte, remainingLength)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	randomString := fmt.Sprintf("%s%s", str, string(b))
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
	log.Println("Barcode generated and saved to : " + filename)
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

	log.Printf("Barcode generated and saved to : %s\n", filename)
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

	log.Printf("QR code generated and saved to : %s\n", filename)
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

func Encrypt(plainText, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Generate a random initialization vector (IV)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(crand.Reader, iv); err != nil {
		return "", err
	}

	// Apply AES encryption in CBC mode
	ciphertext := make([]byte, aes.BlockSize+len(plainText))
	ivCopy := ciphertext[:aes.BlockSize]
	copy(ivCopy, iv)
	cfb := cipher.NewCFBEncrypter(block, ivCopy)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], plainText)

	// Encode the encrypted data in base64
	encrypted := base64.StdEncoding.EncodeToString(ciphertext)
	return encrypted, nil
}

func Decrypt(encrypted string, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext length")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Apply AES decryption in CBC mode
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func GenerateEncryptionKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := crand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func SaveToRegistry(keyVal, strVal string) error {
	// Open the registry key
	key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()

	// Set the string value in the registry key
	err = key.SetStringValue(keyVal, strVal)
	if err != nil {
		return err
	}

	return nil
}

func GetFromRegistry(keyVal string) (string, error) {
	// Open the registry key
	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.READ)
	if err != nil {
		return "", err
	}
	defer key.Close()

	// Read the string value from the registry key
	value, _, err := key.GetStringValue(keyVal)
	if err != nil {
		return "", err
	}

	return value, nil
}

func DeleteRegistryValue(keyVal string) error {
	// Open the registry key
	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()

	// Delete the value from the registry key
	err = key.DeleteValue(keyVal)
	if err != nil {
		return err
	}
	return nil
}

func GeneratePassword(length int, isUsingCompleteSpecialChars bool) string {
	var (
		chars  string
		result strings.Builder
	)

	// Add characters based on the desired complexity
	chars += uppercaseLetters
	chars += lowercaseLetters
	chars += digits

	if isUsingCompleteSpecialChars {
		chars += completeSpecialChars
	} else {
		chars += specialChars
	}

	// Generate random password
	for i := 0; i < length; i++ {
		index, err := crand.Int(crand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			log.Println("Error generating random number : ", err)
			return ""
		}
		result.WriteByte(chars[index.Int64()])
	}

	return result.String()
}

func CalculateIdealBodyWeight(height float64, isMale bool) float64 {
	var baseWeight float64

	if isMale {
		baseWeight = 52 + 1.9*(height-152.4)/2.54
	} else {
		baseWeight = 49 + 1.7*(height-152.4)/2.54
	}

	return baseWeight
}

type CustomLogger struct {
	file   *os.File
	logger *log.Logger
}

func (c *CustomLogger) Log(message string) {
	c.logger.Println(message)
	log.Println(message)
}

func (c *CustomLogger) Close() {
	c.file.Close()
}

func InitializeLog(logFileName string) (*CustomLogger, error) {
	file, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	logger := log.New(file, "", log.Ldate|log.Ltime)

	return &CustomLogger{
		file:   file,
		logger: logger,
	}, nil
}

func RegistryNameExists(name string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.READ)
	if err != nil {
		return false
	}
	defer k.Close()

	_, _, err = k.GetStringValue(name)
	return err == nil
}

// GenerateBase64TOTP generates a Time-based One-Time Password (TOTP) for the given secret key.
func GenerateBase64TOTP(secret string) (string, error) {
	secret = strings.ToUpper(secret)
	// decodedKey, err := base32.StdEncoding.DecodeString(secret)
	decodedKey, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	interval := time.Now().Unix() / timeStepSecs
	msg := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		msg[i] = byte(interval & 0xFF)
		interval >>= 8
	}

	hmacSha1 := hmac.New(sha1.New, decodedKey)
	hmacSha1.Write(msg)
	hmacResult := hmacSha1.Sum(nil)

	offset := hmacResult[len(hmacResult)-1] & 0x0F
	truncatedHash := BinaryToInt(hmacResult[offset:offset+4]) & 0x7FFFFFFF
	otp := truncatedHash % PowerOfTen(digitCount)

	return fmt.Sprintf("%0*d", digitCount, otp), nil
}

func BinaryToInt(data []byte) int {
	val := 0
	for _, b := range data {
		val <<= 8
		val |= int(b)
	}
	return val
}

func IsStringEmpty(str *string) bool {
	if str == nil {
		return true
	}

	trimmedStr := strings.TrimSpace(*str)
	return trimmedStr == ""
}

func PowerOfTen(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}

func ValidateBase64TOTP(secret, otp string) bool {
	generatedOTP, err := GenerateBase64TOTP(secret)
	if err != nil {
		return false
	}

	return otp == generatedOTP
}

func GenerateBase32TOTP(secret string) (string, error) {
	otpCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", err
	} else {
		return otpCode, nil
	}
}

func ValidateBase32TOTP(secret, totpcode string) bool {
	isValid := totp.Validate(totpcode, secret)
	return isValid
}

// func AttachBarcodeToPDF(inputPDF string, barcodeImage string, outputPDF string) error {
// 	// Read the input PDF file
// 	pdfContent, err := ioutil.ReadFile(inputPDF)
// 	if err != nil {
// 		return err
// 	}

// 	// Create a new PDF context from the input PDF
// 	ctx, err := pdfcpu.Read(pdfContent, pdfcpu.NewDefaultConfiguration())
// 	if err != nil {
// 		return err
// 	}

// 	// Read the barcode image
// 	barcodeContent, err := ioutil.ReadFile(barcodeImage)
// 	if err != nil {
// 		return err
// 	}

// 	// Add a new page to the PDF for the barcode
// 	ctx.AddPage()
// 	pageCount := len(ctx.PageList)

// 	// Add the barcode image to the new page
// 	err = ctx.AddImageFromBytes(barcodeContent, pdfcpu.ImageHandlingSkip, pageCount, nil)
// 	if err != nil {
// 		return err
// 	}

// 	// Write the modified PDF to the output file
// 	err = api.WritePDFFile(ctx, outputPDF)
// 	if err != nil {
// 		return err
// 	}

// 	log.Printf("Barcode attached to PDF and saved to: %s\n", outputPDF)
// 	return nil
// }
