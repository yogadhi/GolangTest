package main

import (
	gf "GolangTest/Functions"
	eh "GolangTest/Handlers"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

var (
	logger *gf.CustomLogger
	err    error
)

func main() {
	logger, err = gf.InitializeLog("app.log")
	if err != nil {
		fmt.Println(err)
		return
	}

	HandleAPIRequests()

	maxLength := 16
	data := gf.GenerateRandomStringWithDate(true, maxLength)
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

	err = gf.GenerateBarcode(data, barcodeFilename, barcodeWidth, barcodeHeight)
	if err != nil {
		logger.Log(err.Error())
	}

	err = gf.GenerateQRCode(data, qrCodeFilename)
	if err != nil {
		logger.Log(err.Error())
	}

	if !gf.RegistryNameExists(regNameEncKey) {
		encryptionkey, err = gf.GenerateEncryptionKey()
		if err != nil {
			logger.Log("Error generating encryption key : " + err.Error())
			return
		} else {
			// encryptionKeyStr = hex.EncodeToString(encryptionkey)
			encryptionKeyStr = base64.StdEncoding.EncodeToString(encryptionkey)

			if !gf.IsStringEmpty(&encryptionKeyStr) {
				logger.Log("Generated Encryption Key : " + encryptionKeyStr)

				err = gf.SaveToRegistry(regNameEncKey, encryptionKeyStr)
				if err != nil {
					logger.Log("Error saving value to the registry : " + err.Error())
					return
				} else {
					logger.Log("Generated Encryption Key saved to Registry")
					// logger.Log("Generated Encryption Key saved to Registry. Registry Name : " + regNameEncKey + ", Value : " + encryptionKeyStr)
				}
			} else {
				logger.Log("Generated Encryption Key is empty")
				return
			}
		}
	} else {
		logger.Log("Registry Name exist : " + regNameEncKey)

		generatedEncKey, errx := gf.GetFromRegistry(regNameEncKey)
		if errx != nil {
			logger.Log("Error getting value from the registry : " + errx.Error())
			return
		} else {
			if !gf.IsStringEmpty(&generatedEncKey) {
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

	if !gf.RegistryNameExists(regNamePwd) {
		generatedPwd = gf.GeneratePassword(12, false)
		if !gf.IsStringEmpty(&generatedPwd) {
			logger.Log("Generated Password : " + generatedPwd)

			encryptedPwd, err := gf.Encrypt([]byte(generatedPwd), encryptionkey)
			if err != nil {
				logger.Log("Encryption error : " + err.Error())
				return
			} else {
				logger.Log("Encrypted Password : " + encryptedPwd)

				err = gf.SaveToRegistry(regNamePwd, encryptedPwd)
				if err != nil {
					logger.Log("Error saving value to the registry : " + err.Error())
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

		generatedPassword, errx := gf.GetFromRegistry(regNamePwd)
		if errx != nil {
			logger.Log("Error getting value from the registry : " + errx.Error())
			return
		} else {
			if !gf.IsStringEmpty(&generatedPassword) {
				logger.Log("Value retrieved from the registry : " + generatedPassword)

				decryptedPwd, err := gf.Decrypt(generatedPassword, encryptionkey)
				if err != nil {
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

	totp, err = gf.GenerateBase64TOTP(encryptionKeyStr)
	if err != nil {
		logger.Log("Error generating Base64 TOTP : " + err.Error())
	} else {
		logger.Log("Generated Base64 TOTP : " + totp)
	}

	valid := gf.ValidateBase64TOTP(encryptionKeyStr, totp)
	if valid {
		logger.Log("Base64 OTP is valid.")
	} else {
		logger.Log("Base64 OTP is invalid.")
	}

	totp, err = gf.GenerateBase32TOTP(base32.StdEncoding.EncodeToString(encryptionkey))
	if err != nil {
		logger.Log("Error generating Base32 TOTP : " + err.Error())
	} else {
		logger.Log("Generated Base32 TOTP : " + totp)
	}

	valid = gf.ValidateBase32TOTP(base32.StdEncoding.EncodeToString(encryptionkey), totp)
	if valid {
		logger.Log("Base32 OTP is valid.")
	} else {
		logger.Log("Base32 OTP is invalid.")
	}

	logger.Log("=========================================================================")
	// err = gf.DeleteRegistryValue(registryKey)
	// if err != nil {
	// 	fmt.Println("Error deleting registry value:", err)
	// 	return
	// }
	// fmt.Println("Registry value deleted successfully.")
}

// homePage Function
func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "GoLang Minimal API")
	fmt.Println("Endpoint Hit: homePage")
}

func HandleAPIRequests() {
	eh.Block{
		Try: func() {
			port := "8080"
			myRouter := mux.NewRouter()
			api := myRouter.PathPrefix("/statementAPI").Subrouter()
			api.HandleFunc("/", homePage)
			// api.HandleFunc("/execproducer", ExecuteProducer).Methods("POST")

			if os.Getenv("ASPNETCORE_PORT") != "" {
				port = os.Getenv("ASPNETCORE_PORT")
				fmt.Println(port)
			}

			timeNow := time.Now().Format("2006-01-02 15:04:05")
			logger.Log("Start API")
			fmt.Println(timeNow, "Listening to Port", port+"..")
			muxWithMiddlewares := http.TimeoutHandler(myRouter, time.Minute*180, "Timeout!")
			log.Fatal(http.ListenAndServe(":"+port, muxWithMiddlewares))
		},
		Catch: func(e eh.Exception) {
			ex := fmt.Sprint(e)
			logger.Log(gf.GetFunctionName(HandleAPIRequests) + " " + ex)
		},
	}.Do()
}
