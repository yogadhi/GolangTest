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
	logger, _     = gf.InitializeLog("app.log")
	SIGNATURE_KEY = "aa20fbadd540eee90bc48834ba9be4d842510bd5fd356e78afbc01655369ee88"
)

func main() {
	// fmt.Println(gf.GenerateUUID(false))
	// enc := gf.Encrypt(SIGNATURE_KEY, "e8999895741a4ef49c9ddf62a7409640|Yoga|Quote123!")
	// dec := gf.Decrypt(SIGNATURE_KEY, enc)
	// fmt.Println(SIGNATURE_KEY, enc, dec)
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
