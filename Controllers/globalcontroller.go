package globalcontroller

import (
	gf "GolangTest/Functions"
	eh "GolangTest/Handlers"
	jsm "GolangTest/Models/jsonmodel"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

var (
	logger, _        = gf.InitializeLog("app.log")
	conf             = gf.OpenConfig("config.json")
	JWTSigningMethod = jwt.SigningMethodHS256
	SecretKey        = "Quote123!"
)

func MiddlewareJWTAuthorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// if r.URL.Path == "/login" {
		// 	next.ServeHTTP(w, r)
		// 	return
		// }

		authorizationHeader := r.Header.Get("Authorization")
		if !strings.Contains(authorizationHeader, "Bearer") {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		tokenString := strings.Replace(authorizationHeader, "Bearer ", "", -1)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Signing method invalid")
			} else if method != JWTSigningMethod {
				return nil, fmt.Errorf("Signing method invalid")
			}

			return conf.SignatureKey, nil
		})

		if err != nil {
			logger.Log(gf.GetFunctionName(MiddlewareJWTAuthorization) + " - " + err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ctx := context.WithValue(context.Background(), "userInfo", claims)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func MiddlewareAuthorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dateLayout := "2006-01-02"
		IPAddress := gf.ReadUserIP(r)
		logger.Log(IPAddress + " - " + r.URL.Path + " - " + r.Header.Get("User-Agent") + " - " + r.Header.Get("X-Forwarded-For"))

		ObjToken := gf.ExtractHTTPAuth(w, r)
		if ObjToken == nil {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		if ObjToken.SecretKey != SecretKey {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		expDate, err := time.Parse(dateLayout, ObjToken.ExpDate)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		difference := expDate.Sub(time.Now())
		differenceDay := difference.Hours() / 24
		if differenceDay <= 0 {
			http.Error(w, "Account suspended due to expired", http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func HomePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "GoLang Minimal API")
	fmt.Println("Endpoint Hit: homePage")
}

func GenerateOTP(w http.ResponseWriter, r *http.Request) {
	eh.Block{
		Try: func() {
			w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

			if r.Method != "POST" {
				http.Error(w, "Unsupported http method", http.StatusBadRequest)
				return
			}

			var (
				res                 jsm.GenerateOTPRes
				deviceIDByte        []byte
				deviceIDByteEncoded string
				err                 error
			)

			timeStart := time.Now()
			res.DateReq = timeStart.Format("2006-01-02 15:04:05")
			ObjToken := gf.ExtractHTTPAuth(w, r)
			deviceIDByte = []byte(ObjToken.DeviceID)
			deviceIDByteEncoded = base64.StdEncoding.EncodeToString(deviceIDByte)
			if !gf.IsStringEmpty(&deviceIDByteEncoded) {
				res.TOTP, err = gf.GenerateBase64TOTP(deviceIDByteEncoded)
				if err != nil {
					logger.Log(gf.GetFunctionName(GenerateOTP) + " - " + err.Error())
					res.ErrMsg = err.Error()
				} else {
					res.DateExp = timeStart.Add(30 * time.Second).Format("2006-01-02 15:04:05")
				}
			}
			json.NewEncoder(w).Encode(res)
		},
		Catch: func(e eh.Exception) {
			ex := fmt.Sprint(e)
			logger.Log(gf.GetFunctionName(GenerateOTP) + " - " + ex)
		},
	}.Do()
}

func ValidateOTP(w http.ResponseWriter, r *http.Request) {
	eh.Block{
		Try: func() {
			w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

			if r.Method != "POST" {
				http.Error(w, "Unsupported http method", http.StatusBadRequest)
				return
			}

			var (
				req                 jsm.ValidateOTPReq
				res                 jsm.ValidateOTPRes
				deviceIDByte        []byte
				deviceIDByteEncoded string
			)

			reqBody, _ := io.ReadAll(r.Body)
			err := json.Unmarshal(reqBody, &req)
			if err != nil {
				logger.Log(gf.GetFunctionName(ValidateOTP) + " - " + err.Error())
				res.ErrMsg = err.Error()
				json.NewEncoder(w).Encode(res)
				return
			}

			ObjToken := gf.ExtractHTTPAuth(w, r)
			deviceIDByte = []byte(ObjToken.DeviceID)
			deviceIDByteEncoded = base64.StdEncoding.EncodeToString(deviceIDByte)
			if !gf.IsStringEmpty(&deviceIDByteEncoded) {
				res.IsTOTPValid = gf.ValidateBase64TOTP(deviceIDByteEncoded, req.TOTP)
			}

			json.NewEncoder(w).Encode(res)
		},
		Catch: func(e eh.Exception) {
			ex := fmt.Sprint(e)
			logger.Log(gf.GetFunctionName(ValidateOTP) + " - " + ex)
		},
	}.Do()
}

func GoEncrypt(w http.ResponseWriter, r *http.Request) {
	eh.Block{
		Try: func() {

			w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

			if r.Method != "POST" {
				http.Error(w, "Unsupported http method", http.StatusBadRequest)
				return
			}

			var (
				req jsm.GoEncryptReq
				res jsm.GoEncryptRes
			)

			reqBody, _ := io.ReadAll(r.Body)
			err := json.Unmarshal(reqBody, &req)
			if err != nil {
				logger.Log(gf.GetFunctionName(GoEncrypt) + " - " + err.Error())
				json.NewEncoder(w).Encode(res)
				return
			}

			if req.PlainText == "" {
				return
			}

			if req.Key == "" {
				return
			}

			res.EncryptedText = gf.Encrypt(req.Key, req.PlainText)
			json.NewEncoder(w).Encode(res)
		},
		Catch: func(e eh.Exception) {
			ex := fmt.Sprint(e)
			logger.Log(gf.GetFunctionName(GoEncrypt) + " - " + ex)
		},
	}.Do()
}

func GoDecrypt(w http.ResponseWriter, r *http.Request) {
	eh.Block{
		Try: func() {
			w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

			if r.Method != "POST" {
				http.Error(w, "Unsupported http method", http.StatusBadRequest)
				return
			}

			var (
				req jsm.GoDecryptReq
				res jsm.GoDecryptRes
			)

			reqBody, _ := io.ReadAll(r.Body)
			err := json.Unmarshal(reqBody, &req)
			if err != nil {
				logger.Log(gf.GetFunctionName(GoEncrypt) + " - " + err.Error())
				json.NewEncoder(w).Encode(res)
				return
			}

			if req.EncryptedText == "" {
				return
			}

			if req.Key == "" {
				return
			}

			res.DecryptedText = gf.Decrypt(req.Key, req.EncryptedText)
			json.NewEncoder(w).Encode(res)
		},
		Catch: func(e eh.Exception) {
			ex := fmt.Sprint(e)
			logger.Log(gf.GetFunctionName(GoEncrypt) + " - " + ex)
		},
	}.Do()
}
