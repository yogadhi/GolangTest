package main

import (
	ctrllr "GolangTest/Controllers"
	gf "GolangTest/Functions"
	eh "GolangTest/Handlers"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/gorilla/mux"
)

var (
	logger, _ = gf.InitializeLog("app.log")
	conf      = gf.OpenConfig("config.json")
)

func main() {
	err := gf.DownloadFile("C:\\WinSvc\\DownloadedFiles\\SSE_Securities.csv", "https://www.hkex.com.hk/-/media/HKEX-Market/Mutual-Market/Stock-Connect/Eligible-Stocks/View-All-Eligible-Securities/SSE_Securities.csv")
	if err != nil {
		logger.Log(gf.GetFunctionName(main) + " " + err.Error())
	}
	// DummyFunc()
	// HandleAPIRequests(false)
}

func HandleAPIRequests(isUsingTLS bool) {
	mainPathPrefix := "/MiniAPI"
	subPathPrefix := "/"
	apiName := ""

	eh.Block{
		Try: func() {
			port := conf.Port
			myRouter := mux.NewRouter()
			api := myRouter.PathPrefix(mainPathPrefix).Subrouter()
			api.Handle("/", http.HandlerFunc(ctrllr.HomePage))

			apiName = path.Join(subPathPrefix, gf.GetFunctionName(ctrllr.GenerateOTP))
			api.Handle(apiName, ctrllr.MiddlewareAuthorization(http.HandlerFunc(ctrllr.GenerateOTP)))

			apiName = path.Join(subPathPrefix, gf.GetFunctionName(ctrllr.ValidateOTP))
			api.Handle(apiName, ctrllr.MiddlewareAuthorization(http.HandlerFunc(ctrllr.ValidateOTP)))

			apiName = path.Join(subPathPrefix, gf.GetFunctionName(ctrllr.GoEncrypt))
			api.Handle(apiName, http.HandlerFunc(ctrllr.GoEncrypt))

			apiName = path.Join(subPathPrefix, gf.GetFunctionName(ctrllr.GoDecrypt))
			api.Handle(apiName, http.HandlerFunc(ctrllr.GoDecrypt))

			if os.Getenv("ASPNETCORE_PORT") != "" {
				port = os.Getenv("ASPNETCORE_PORT")
				logger.Log(port)
			}

			if isUsingTLS {
				cfg := &tls.Config{
					MinVersion:               tls.VersionTLS12,
					CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
					PreferServerCipherSuites: true,
					CipherSuites: []uint16{
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
				}

				srv := &http.Server{
					Addr:         ":" + conf.TLSPort,
					Handler:      api,
					TLSConfig:    cfg,
					TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
				}
				log.Fatal(srv.ListenAndServeTLS("tls.crt", "tls.key"))
			} else {
				timeNow := time.Now().Format("2006-01-02 15:04:05")
				logger.Log("Start API")
				logger.Log(timeNow + " Listening to Port " + port + "..")
				muxWithMiddlewares := http.TimeoutHandler(myRouter, time.Minute*180, "Request Timeout")
				log.Fatal(http.ListenAndServe(":"+port, muxWithMiddlewares))
			}
		},
		Catch: func(e eh.Exception) {
			ex := fmt.Sprint(e)
			logger.Log(gf.GetFunctionName(HandleAPIRequests) + " " + ex)
		},
	}.Do()
}

func DummyFunc() {
	randomStr := gf.GenerateRandomString(false, 32)
	randomByte := []byte(randomStr)
	encodedRandomByte := base64.StdEncoding.EncodeToString(randomByte)
	conf.SignatureKey = encodedRandomByte //"UlhOVlNYSFhVUk82WlgzTzRRTlpHTFhVMFJROUhDTkg="

	bearerToken := "vIu76Vsh_wLRg_51npQwDWv4MUA20OMQSFteFvOQfDrs6fmbN3en2iHjqzYiuH2neQPn6RtFgCPPzHZTBrHcadt4nBx9LXkIIjuLQkVgejkqdjnaNz5BfrgxviAKc6uN-LU4MKKCkkIPEvcb8VznGbD7ukw2"
	deviceID := "36860be0a7330597ccde4b7e1babf88e"
	userID := "C2D23201-CF18-41C7-9A5F-50A2948B8792"
	registerDate := time.Now()
	expiredDate := registerDate.AddDate(1, 0, 0)
	tokenFormat := "Quote123!|" + userID + "|" + deviceID + "|" + registerDate.Format("2006-01-02") + "|" + expiredDate.Format("2006-01-02")

	tokenFormatEnc := gf.Encrypt(conf.SignatureKey, tokenFormat)
	tokenFormatDec := gf.Decrypt(conf.SignatureKey, tokenFormatEnc)

	fmt.Println("Signature Key:", conf.SignatureKey)
	fmt.Println("Token Format Encrypted:", tokenFormatEnc)
	fmt.Println("Token Format Decrypted:", tokenFormatDec)
	fmt.Println("Device ID:", gf.GenerateDeviceID())
	fmt.Println("UUID:", gf.GenerateUUID(true))
	fmt.Println("Bearer Token:", bearerToken)

	totp, _ := gf.GenerateBase64TOTP(conf.SignatureKey)
	fmt.Println("TOTP:", totp)

	x, y := gf.CalculatePercentageChange(8500000, 8900000)
	fmt.Println(x, y)

	enc, _ := gf.EncryptString("b14ca5898a4e4133bbce2ea2315a1916", "c2d23201-cf18-41c7-9a5f-50a2948b8792|36860be0a7330597ccde4b7e1babf88e|2023-08-03|2024-08-03")
	dec, _ := gf.DecryptString("b14ca5898a4e4133bbce2ea2315a1916", enc)
	fmt.Println(enc)
	fmt.Println("asdasdda", dec)
}
