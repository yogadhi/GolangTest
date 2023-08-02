package main

import (
	controller "GolangTest/Controllers"
	gf "GolangTest/Functions"
	eh "GolangTest/Handlers"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

var (
	logger, _ = gf.InitializeLog("app.log")
	conf      = gf.OpenConfig("config.json")
)

func main() {
	// bearerToken := "ZRIVxneln3622phoMs13ZY1RAqTpxNFZUgsY7I-4WlLAyUU-GdrYENwLBZq7tgysFA0xKcsQ1IPgw7W9jotV-n4qZ3BUEq9ZFAOUlfRbnWWe48cGcFKPpXe_JJZ_4OHneiK29J3vJrIuADQ="
	// deviceID := "36860be0a7330597ccde4b7e1babf88e"
	// userID := "c2d23201-cf18-41c7-9a5f-50a2948b8792"
	// registerDate := time.Now()
	// expiredDate := registerDate.AddDate(1, 0, 0)
	// tokenFormat := userID + "|" + deviceID + "|" + registerDate.Format("2006-01-02") + "|" + expiredDate.Format("2006-01-02")
	// tokenFormatEnc := gf.Encrypt(conf.SignatureKey, tokenFormat)
	// tokenFormatDec := gf.Decrypt(conf.SignatureKey, tokenFormatEnc)
	// fmt.Println("Signature Key:", conf.SignatureKey)
	// fmt.Println("Token Format Encrypted:", tokenFormatEnc)
	// fmt.Println("Token Format Decrypted", tokenFormatDec)
	// fmt.Println(gf.GenerateDeviceID())
	// fmt.Println(gf.GenerateUUID(true))
	HandleAPIRequests()
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
			api := myRouter.PathPrefix("/MiniAPI").Subrouter()
			api.Handle("/", controller.MiddlewareAuthorization(http.HandlerFunc(homePage)))
			api.Handle("/GenerateOTP", controller.MiddlewareAuthorization(http.HandlerFunc(controller.GenerateOTP)))
			api.Handle("/ValidateOTP", controller.MiddlewareAuthorization(http.HandlerFunc(controller.ValidateOTP)))

			if os.Getenv("ASPNETCORE_PORT") != "" {
				port = os.Getenv("ASPNETCORE_PORT")
				logger.Log(port)
			}

			// cfg := &tls.Config{
			// 	MinVersion:               tls.VersionTLS12,
			// 	CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			// 	PreferServerCipherSuites: true,
			// 	CipherSuites: []uint16{
			// 		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			// 		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			// 		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// 		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			// 	},
			// }

			// srv := &http.Server{
			// 	// Addr:         ":443",
			// 	Handler:      myRouter,
			// 	TLSConfig:    cfg,
			// 	TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
			// }

			timeNow := time.Now().Format("2006-01-02 15:04:05")
			logger.Log("Start API")
			logger.Log(timeNow + " Listening to Port " + port + "..")
			muxWithMiddlewares := http.TimeoutHandler(myRouter, time.Minute*180, "Request Timeout")
			log.Fatal(http.ListenAndServe(":"+port, muxWithMiddlewares))
			// log.Fatal(srv.ListenAndServeTLS("tls.crt", "tls.key"))
		},
		Catch: func(e eh.Exception) {
			ex := fmt.Sprint(e)
			logger.Log(gf.GetFunctionName(HandleAPIRequests) + " " + ex)
		},
	}.Do()
}
