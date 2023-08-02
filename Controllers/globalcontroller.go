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
	ObjToken         jsm.Token
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
		IPAddress := gf.ReadUserIP(r)
		logger.Log(IPAddress + " - " + r.URL.Path)

		authorizationHeader := r.Header.Get("Authorization")
		if !strings.Contains(authorizationHeader, "Bearer") {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		tokenString := strings.Replace(authorizationHeader, "Bearer ", "", -1)

		token := gf.Decrypt(conf.SignatureKey, tokenString)

		tokenArr := strings.Split(token, "|")
		if tokenArr == nil {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		if len(tokenArr) != 4 {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		dateLayout := "2006-01-02"

		ObjToken = jsm.Token{
			UserID:   tokenArr[0],
			DeviceID: tokenArr[1],
			RegDate:  tokenArr[2],
			ExpDate:  tokenArr[3],
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

		//can add custom logic validation here

		next.ServeHTTP(w, r)
	})
}

func GenerateOTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

	if r.Method != "POST" {
		http.Error(w, "Unsupported http method", http.StatusBadRequest)
		return
	}

	var (
		// req                 jsm.GenerateOTPReq
		res                 jsm.GenerateOTPRes
		deviceIDByte        []byte
		deviceIDByteEncoded string
		err                 error
	)

	eh.Block{
		Try: func() {
			// reqBody, _ := io.ReadAll(r.Body)
			// err := json.Unmarshal(reqBody, &req)
			// if err != nil {
			// 	logger.Log(gf.GetFunctionName(GenerateOTP) + " - " + err.Error())
			// 	res.ErrMsg = err.Error()
			// 	json.NewEncoder(w).Encode(res)
			// 	return
			// }

			timeStart := time.Now()
			res.DateReq = timeStart.Format("2006-01-02 15:04:05")
			// deviceIDByte = []byte(req.DeviceID)
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

	eh.Block{
		Try: func() {
			reqBody, _ := io.ReadAll(r.Body)
			err := json.Unmarshal(reqBody, &req)
			if err != nil {
				logger.Log(gf.GetFunctionName(ValidateOTP) + " - " + err.Error())
				res.ErrMsg = err.Error()
				json.NewEncoder(w).Encode(res)
				return
			}

			// deviceIDByte = []byte(req.DeviceID)
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
