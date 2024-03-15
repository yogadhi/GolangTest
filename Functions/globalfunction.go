package globalfunction

import (
	eh "GolangTest/Handlers"
	jm "GolangTest/Models/jsonmodel"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"log"
	"math"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/google/uuid"
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
)

var (
	logger, err = InitializeLog("app.log")
	conf        = OpenConfig("config.json")

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

type CustomLogger struct {
	file   *os.File
	logger *log.Logger
}

func globalfunction() {

}

func GroupedFunction() {
	maxLength := 16
	data := GenerateRandomString(true, maxLength)
	logger.Log("Random string : " + data)

	barcodeWidth := 200
	barcodeHeight := 75
	barcodeFilename := "barcode.png"
	qrCodeFilename := "qrcode.png"

	regNamePwd := "GeneratedPassword"
	regNameEncKey := "GeneratedEncyptionKey"
	var encryptionkey []byte
	var encryptionKeyStr string
	var generatedPwd string
	var totp string

	GenerateBarcode(data, barcodeFilename, barcodeWidth, barcodeHeight)

	GenerateQRCode(data, qrCodeFilename)

	if !RegistryNameExists(regNameEncKey) {
		encryptionkey = []byte(GenerateRandomString(false, 32))
		if encryptionkey == nil {
			logger.Log("Error generating encryption key : " + err.Error())
			return
		} else {
			// encryptionKeyStr = hex.EncodeToString(encryptionkey)
			encryptionKeyStr = base64.StdEncoding.EncodeToString(encryptionkey)

			if !IsStringEmpty(&encryptionKeyStr) {
				logger.Log("Generated Encryption Key : " + encryptionKeyStr)

				if !SaveToRegistry(regNameEncKey, encryptionKeyStr) {
					return
				} else {
					logger.Log("Generated Encryption Key saved to Registry")
				}
			} else {
				logger.Log("Generated Encryption Key is empty")
				return
			}
		}
	} else {
		logger.Log("Registry Name exist : " + regNameEncKey)

		generatedEncKey := GetFromRegistry(regNameEncKey)
		if IsStringEmpty(&generatedEncKey) {
			return
		} else {
			if !IsStringEmpty(&generatedEncKey) {
				logger.Log("Value retrieved from the registry : " + generatedEncKey)
				// encryptionkey = []byte(generatedEncKey)
				encryptionkey, err = base64.StdEncoding.DecodeString(generatedEncKey)
				if err != nil {
					fmt.Println("Base64 decoding error:", err)
					return
				}
			} else {
				logger.Log("Generated Encryption Key is empty")
				return
			}
		}
	}

	if !RegistryNameExists(regNamePwd) {
		generatedPwd = GeneratePassword(12, false)
		if !IsStringEmpty(&generatedPwd) {
			logger.Log("Generated Password : " + generatedPwd)

			encryptedPwd := Encrypt(encryptionKeyStr, generatedPwd)
			if IsStringEmpty(&encryptedPwd) {
				logger.Log("Encryption error : " + err.Error())
				return
			} else {
				logger.Log("Encrypted Password : " + encryptedPwd)

				if !SaveToRegistry(regNamePwd, encryptedPwd) {
					return
				} else {
					logger.Log("Encrypted Password saved to Registry.")
					// logger.Log("Encrypted Password saved to Registry. Registry Name : " + regNamePwd + ", Value : " + encryptedPwd)
				}
			}
		} else {
			logger.Log("Generated Password is empty")
			return
		}
	} else {
		logger.Log("Registry Name exist : " + regNamePwd)

		generatedPassword := GetFromRegistry(regNamePwd)
		if IsStringEmpty(&generatedPassword) {
			return
		} else {
			if !IsStringEmpty(&generatedPassword) {
				logger.Log("Value retrieved from the registry : " + generatedPassword)

				decryptedPwd := Decrypt(encryptionKeyStr, generatedPassword)
				if IsStringEmpty(&decryptedPwd) {
					logger.Log("Decryption error : " + err.Error())
					return
				} else {
					logger.Log("Decrypted Password : " + decryptedPwd)
				}
			} else {
				logger.Log("Generated Password is empty")
				return
			}
		}
	}

	totp, err = GenerateBase64TOTP(encryptionKeyStr)
	if err != nil {
		logger.Log("Error generating Base64 TOTP : " + err.Error())
	} else {
		logger.Log("Generated Base64 TOTP : " + totp)
	}

	valid := ValidateBase64TOTP(encryptionKeyStr, totp)
	if valid {
		logger.Log("Base64 OTP is valid.")
	} else {
		logger.Log("Base64 OTP is invalid.")
	}

	totp, err = GenerateBase32TOTP(base32.StdEncoding.EncodeToString(encryptionkey))
	if err != nil {
		logger.Log("Error generating Base32 TOTP : " + err.Error())
	} else {
		logger.Log("Generated Base32 TOTP : " + totp)
	}

	valid = ValidateBase32TOTP(base32.StdEncoding.EncodeToString(encryptionkey), totp)
	if valid {
		logger.Log("Base32 OTP is valid.")
	} else {
		logger.Log("Base32 OTP is invalid.")
	}

	if !DeleteRegistryValue(regNamePwd) {
		logger.Log("Error deleting registry value: " + err.Error())
		return
	} else {
		logger.Log("Registry value deleted successfully.")
	}
	logger.Log("=========================================================================")
}

func GetFunctionName(i interface{}) string {
	res := ""

	strFuncName := runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
	if strFuncName != "" {
		if strings.Contains(strFuncName, ".") {
			listFuncName := strings.Split(strFuncName, ".")
			if listFuncName != nil {
				if len(listFuncName) > 0 {
					res = listFuncName[len(listFuncName)-1]
				}
			}
		}
	}
	return res
}

func GenerateRandomString(isUsingDate bool, maxLength int) string {
	str := ""

	if isUsingDate {
		str = time.Now().Format("20060102") // Format date as YYYYMMDD
	}

	remainingLength := maxLength - len(str)
	if remainingLength <= 0 {
		return strings.ToUpper(str)
	}

	// rand.Seed(time.Now().UnixNano())
	rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, remainingLength)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	randomString := fmt.Sprintf("%s%s", str, string(b))
	return strings.ToUpper(randomString)
}

func GenerateBarcode(data string, filename string, width, height int) bool {
	// data that will be encoded into our barcode
	// Generate a new writer for Code 128 barcode
	// this format allows you to encode all ASCII characters!
	writer := oned.NewCode128Writer()
	// with the writer, we can start encoding!
	img, err := writer.Encode(data, gozxing.BarcodeFormat_CODE_128, width, height, nil)
	if err != nil {
		logger.Log(GetFunctionName(GenerateBarcode) + " - " + err.Error())
		return false
	}
	// create a file that will hold our barcode
	file, err := os.Create("barcode.png")
	if err != nil {
		logger.Log(GetFunctionName(GenerateBarcode) + " - " + err.Error())
		return false
	}
	defer file.Close()
	// Encode the image in PNG
	err = png.Encode(file, img)
	if err != nil {
		logger.Log(GetFunctionName(GenerateBarcode) + " - " + err.Error())
		return false
	} else {
		logger.Log("Barcode generated and saved to : " + filename)
		return true
	}
}

func GenerateBarcodeCustom(data string, filename string) bool {
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
		logger.Log(GetFunctionName(GenerateBarcodeCustom) + " - " + err.Error())
		return false
	}
	defer file.Close()

	err = png.Encode(file, img)
	if err != nil {
		logger.Log(GetFunctionName(GenerateBarcodeCustom) + " - " + err.Error())
		return false
	} else {
		logger.Log("Barcode generated and saved to : " + filename)
		return false
	}
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

func GenerateQRCode(data string, filename string) bool {
	// Create a new QR code with the specified data and correction level
	qrCode, err := qr.Encode(data, qr.L, qr.Auto)
	if err != nil {
		logger.Log(GetFunctionName(GenerateQRCode) + " - " + err.Error())
		return false
	}

	// Scale the QR code to the desired width and height
	qrCode, err = barcode.Scale(qrCode, 200, 200)
	if err != nil {
		logger.Log(GetFunctionName(GenerateQRCode) + " - " + err.Error())
		return false
	}

	// Create a new file to save the QR code image
	file, err := os.Create(filename)
	if err != nil {
		logger.Log(GetFunctionName(GenerateQRCode) + " - " + err.Error())
		return false
	}
	defer file.Close()

	// Encode the QR code as PNG and save it to the file
	err = png.Encode(file, qrCode)
	if err != nil {
		logger.Log(GetFunctionName(GenerateQRCode) + " - " + err.Error())
		return false
	} else {
		logger.Log("QR code generated and saved to : " + filename)
		return false
	}
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

func GenerateKeyString() string {
	randomStr := GenerateRandomString(false, 32)
	return hex.EncodeToString([]byte(randomStr))
}

func Encrypt(keyString string, stringToEncrypt string) string {

	// convert key to bytes
	key, _ := base64.StdEncoding.DecodeString(keyString)
	// key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Log(GetFunctionName(Encrypt) + " - " + err.Error())
		return ""
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(crand.Reader, iv); err != nil {
		logger.Log(GetFunctionName(Encrypt) + " - " + err.Error())
		return ""
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

func EncryptString(key, plainText string) (string, error) {
	// Convert the key to bytes
	keyBytes := []byte(key)

	// Initialize the IV as a 16-byte array filled with zeros
	iv := make([]byte, aes.BlockSize)

	// Convert the plain text to bytes
	plainTextBytes := []byte(plainText)

	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Create a new byte slice to store the encrypted data
	ciphertext := make([]byte, aes.BlockSize+len(plainTextBytes))

	// Copy the IV to the beginning of the ciphertext slice
	copy(ciphertext, iv)

	// Create a new AES CFB encrypter
	stream := cipher.NewCFBEncrypter(block, iv)

	// Encrypt the plain text and store the result in the remaining bytes of the ciphertext slice
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plainTextBytes)

	// Convert the ciphertext to a base64-encoded string
	encrypted := base64.StdEncoding.EncodeToString(ciphertext)

	return encrypted, nil
}

func Decrypt(keyString string, stringToDecrypt string) string {
	// key, _ := hex.DecodeString(keyString)
	key, _ := base64.StdEncoding.DecodeString(keyString)
	ciphertext, _ := base64.URLEncoding.DecodeString(stringToDecrypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Log(GetFunctionName(Decrypt) + " - " + err.Error())
		return ""
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		logger.Log(GetFunctionName(Decrypt) + " - " + err.Error())
		return ""
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}

func DecryptString(key, cipherText string) (string, error) {
	// Convert the key to bytes
	keyBytes := []byte(key)

	// Initialize the IV as a 16-byte array filled with zeros
	iv := make([]byte, aes.BlockSize)

	// Convert the base64-encoded ciphertext to bytes
	ciphertext, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Create a new AES CFB decrypter
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt the ciphertext and store the result in a new byte slice
	decrypted := make([]byte, len(ciphertext))
	stream.XORKeyStream(decrypted, ciphertext)

	return string(decrypted), nil
}

func SaveToRegistry(keyVal, strVal string) bool {
	// Open the registry key
	key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		logger.Log(GetFunctionName(SaveToRegistry) + " - " + err.Error())
		return false
	}
	defer key.Close()

	// Set the string value in the registry key
	err = key.SetStringValue(keyVal, strVal)
	if err != nil {
		logger.Log(err.Error())
		return false
	} else {
		return true
	}
}

func GetFromRegistry(keyVal string) string {
	// Open the registry key
	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.READ)
	if err != nil {
		logger.Log(GetFunctionName(GetFromRegistry) + " - " + err.Error())
		return ""
	}
	defer key.Close()

	// Read the string value from the registry key
	value, _, err := key.GetStringValue(keyVal)
	if err != nil {
		logger.Log(GetFunctionName(GetFromRegistry) + " - " + err.Error())
		return ""
	} else {
		return value
	}
}

func DeleteRegistryValue(keyVal string) bool {
	// Open the registry key
	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		logger.Log(GetFunctionName(DeleteRegistryValue) + " - " + err.Error())
		return false
	}
	defer key.Close()

	// Delete the value from the registry key
	err = key.DeleteValue(keyVal)
	if err != nil {
		logger.Log(GetFunctionName(DeleteRegistryValue) + " - " + err.Error())
		return false
	} else {
		return true
	}
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
			logger.Log(GetFunctionName(GeneratePassword) + " - " + err.Error())
			return ""
		}
		result.WriteByte(chars[index.Int64()])
	}

	return result.String()
}

func GenerateUUID(isUsingDash bool) string {
	res := ""
	uuidWithHyphen := uuid.New()

	if !isUsingDash {
		res = strings.Replace(uuidWithHyphen.String(), "-", "", -1)
	} else {
		res = uuidWithHyphen.String()
	}
	res = strings.ToUpper(res)
	return res
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
		logger.Log(GetFunctionName(RegistryNameExists) + " - " + err.Error())
		return false
	}
	defer k.Close()

	_, _, err = k.GetStringValue(name)
	return err == nil
}

func GenerateBase64TOTP(secret string) (string, error) {
	secret = strings.ToUpper(secret)
	// decodedKey, err := base32.StdEncoding.DecodeString(secret)
	decodedKey, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		logger.Log(GetFunctionName(GenerateBase64TOTP) + " - " + err.Error())
		return "", err
	}

	interval := time.Now().Unix() / int64(conf.TOTPDuration)
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
	otp := truncatedHash % PowerOfTen(conf.TOTPDigitCount)

	return fmt.Sprintf("%0*d", conf.TOTPDigitCount, otp), nil
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
		logger.Log(GetFunctionName(ValidateBase64TOTP) + " - " + err.Error())
		return false
	}

	return otp == generatedOTP
}

func GenerateBase32TOTP(secret string) (string, error) {
	otpCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		logger.Log(GetFunctionName(GenerateBase32TOTP) + " - " + err.Error())
		return "", err
	} else {
		return otpCode, nil
	}
}

func ValidateBase32TOTP(secret, totpcode string) bool {
	isValid := totp.Validate(totpcode, secret)
	return isValid
}

func ReadUserIP(r *http.Request) string {
	//Get IP from the X-REAL-IP header
	ip := r.Header.Get("X-REAL-IP")
	netIP := net.ParseIP(ip)
	if netIP != nil {
		return ip
	}

	//Get IP from X-FORWARDED-FOR header
	ips := r.Header.Get("X-FORWARDED-FOR")
	splitIps := strings.Split(ips, ",")
	for _, ip := range splitIps {
		netIP := net.ParseIP(ip)
		if netIP != nil {
			return ip
		}
	}

	//Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		logger.Log(GetFunctionName(ReadUserIP) + " - " + err.Error())
		return ""
	}
	netIP = net.ParseIP(ip)
	if netIP != nil {
		return ip
	}
	return ""
}

func OpenConfig(filename string) *jm.Configuration {
	var result *jm.Configuration

	eh.Block{
		Try: func() {
			if _, err := os.Stat(filename); err != nil {
				// SignatureKey:   "aa20fbadd540eee90bc48834ba9be4d842510bd5fd356e78afbc01655369ee88",
				objConfig := jm.Configuration{
					SignatureKey:   "UjUyWVZGQldQNVFJUzJOSkJPT0FZWUlMTU5EM0FUWkc=",
					TOTPDigitCount: 6,
					TOTPDuration:   30,
					Port:           "8080",
					TLSPort:        "443",
				}

				file, _ := json.MarshalIndent(objConfig, "", " ")
				err = os.WriteFile("config.json", file, 0644)
				if err != nil {
					logger.Log(GetFunctionName(OpenConfig) + " - " + err.Error())
					return
				}
			}

			file, err := os.Open(filename)
			if err != nil {
				logger.Log(GetFunctionName(OpenConfig) + " - " + err.Error())
				return
			}

			defer file.Close()

			decoder := json.NewDecoder(file)

			err = decoder.Decode(&result)
			if err != nil {
				logger.Log(GetFunctionName(OpenConfig) + " - " + err.Error())
				return
			}
		},
		Catch: func(e eh.Exception) {
			ex := fmt.Sprint(e)
			logger.Log(GetFunctionName(OpenConfig) + " - " + ex)
		},
	}.Do()

	return result
}

func GenerateDeviceID() string {
	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		logger.Log(GetFunctionName(GenerateDeviceID) + " - " + err.Error())
		return ""
	}

	// Get MAC address
	interfaces, err := net.Interfaces()
	if err != nil {
		logger.Log(GetFunctionName(GenerateDeviceID) + " - " + err.Error())
		return ""
	}

	var macAddr string
	for _, iface := range interfaces {
		if iface.HardwareAddr != nil {
			macAddr = iface.HardwareAddr.String()
			break
		}
	}

	// Get current timestamp
	timestamp := time.Now().Unix()

	// Concatenate the data to create a unique string
	deviceData := fmt.Sprintf("%s-%s-%d", hostname, macAddr, timestamp)

	// Calculate the MD5 hash of the concatenated data
	hash := md5.Sum([]byte(deviceData))

	// Convert the hash to a hexadecimal string and return it as the device ID
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

func GetMACAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		logger.Log(GetFunctionName(GetMACAddress) + " - " + err.Error())
		return ""
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Get the MAC address of the first non-loopback and up interface
		macAddr := iface.HardwareAddr.String()
		if macAddr != "" {
			return macAddr
		}
	}

	return ""
}

func ExtractHTTPAuth(w http.ResponseWriter, r *http.Request) *jm.Token {
	var ObjToken jm.Token

	eh.Block{
		Try: func() {
			authorizationHeader := r.Header.Get("Authorization")
			if !strings.Contains(authorizationHeader, "Bearer") {
				return
			}

			tokenString := strings.Replace(authorizationHeader, "Bearer ", "", -1)
			token := Decrypt(conf.SignatureKey, tokenString)

			tokenArr := strings.Split(token, "|")
			if tokenArr == nil {
				return
			}

			if len(tokenArr) != 5 {
				return
			}

			ObjToken = jm.Token{
				SecretKey: tokenArr[0],
				UserID:    tokenArr[1],
				DeviceID:  tokenArr[2],
				RegDate:   tokenArr[3],
				ExpDate:   tokenArr[4],
			}
		},
		Catch: func(e eh.Exception) {
			ex := fmt.Sprint(e)
			logger.Log(GetFunctionName(ExtractHTTPAuth) + " - " + ex)
		},
	}.Do()
	return &ObjToken
}

func CalculatePercentageChange(oldValue, newValue float64) (roundVal, realVal float64) {
	res := ((newValue - oldValue) / oldValue) * 100
	return RoundWithParam(res, 2), res
}

func RoundToTwoDigits(number float64) float64 {
	return math.Round(number*100) / 100
}

func RoundWithParam(number float64, digits int) float64 {
	scale := math.Pow(10, float64(digits))
	return math.Round(number*scale) / scale
}

func CalculateFromPercentage(percentage, value float64) float64 {
	return (percentage / 100) * value
}

func FormatCurrency(amount float64) string {
	roundedAmount := strconv.FormatFloat(amount, 'f', 2, 64)
	return roundedAmount
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

func DownloadFile(filepath string, url string) error {
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}
