package main

import (
	ctrllr "GolangTest/Controllers"
	gf "GolangTest/Functions"
	eh "GolangTest/Handlers"
	"crypto/tls"
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
	// err := gf.DownloadFile("C:\\WinSvc\\DownloadedFiles\\SSE_Securities.csv", "https://www.hkex.com.hk/-/media/HKEX-Market/Mutual-Market/Stock-Connect/Eligible-Stocks/View-All-Eligible-Securities/SSE_Securities.csv")
	// if err != nil {
	// 	logger.Log(gf.GetFunctionName(main) + " " + err.Error())
	// }
	DummyFunc()
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
	x, y := gf.CalculatePercentageChange(8500000, 8900000)
	fmt.Println("Rounded Value  :", x)
	fmt.Println("Real Value     :", y)

	conf.SignatureKey = gf.GenerateSignatureKey()
	fmt.Println("Signature Key  :", conf.SignatureKey)

	totp, _ := gf.GenerateBase64TOTP(conf.SignatureKey)
	fmt.Println("TOTP           :", totp)

	deviceID := gf.GenerateDeviceID()
	userID := gf.GenerateUUID(true)
	registerDate := time.Now()
	expiredDate := registerDate.AddDate(1, 0, 0)
	tokenFormat := "Quote123!|" + userID + "|" + deviceID + "|" + registerDate.Format("2006-01-02") + "|" + expiredDate.Format("2006-01-02")
	fmt.Println("Token Format   :", tokenFormat)

	enc := gf.Encrypt(conf.SignatureKey, tokenFormat)
	fmt.Println("Bearer Token   :", enc)

	dec := gf.Decrypt(conf.SignatureKey, enc)
	fmt.Println("Decrypt Result :", dec)
}
