package globalcontroller

import (
	gf "GolangTest/Functions"
	eh "GolangTest/Handlers"
	jsm "GolangTest/Models/jsonmodel"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

var (
	logger, err = gf.InitializeLog("app.log")
)

var APPLICATION_NAME = "My Simple JWT App"
var LOGIN_EXPIRATION_DURATION = time.Duration(1) * time.Hour
var JWT_SIGNING_METHOD = jwt.SigningMethodHS256
var SIGNATURE_KEY = "krNWrDNtlT2TVhbxg6LulRWEZ/qS9wXHaj4nwIvHtAg="

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
			} else if method != JWT_SIGNING_METHOD {
				return nil, fmt.Errorf("Signing method invalid")
			}

			return SIGNATURE_KEY, nil
		})

		if err != nil {
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
		authorizationHeader := r.Header.Get("Authorization")
		if !strings.Contains(authorizationHeader, "Bearer") {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		tokenString := strings.Replace(authorizationHeader, "Bearer ", "", -1)

		encryptionkey, err := base64.StdEncoding.DecodeString(SIGNATURE_KEY)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		token := gf.Decrypt(string(encryptionkey), tokenString)
		fmt.Println(token)

		tokenArr := strings.Split(token, "|")
		if tokenArr == nil {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		if len(tokenArr) <= 1 {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}

		//can add custom logic validation here

		next.ServeHTTP(w, r)
	})
}

func GenerateOTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

	var req jsm.GenerateOTPReq
	res := jsm.GenerateOTPRes{
		TOTP:   "",
		ErrMsg: "",
	}

	eh.Block{
		Try: func() {
			logger.Log(gf.GetFunctionName(GenerateOTP))

			reqBody, _ := ioutil.ReadAll(r.Body)
			err := json.Unmarshal(reqBody, &req)
			if err != nil {
				res.ErrMsg = err.Error()
				json.NewEncoder(w).Encode(res)
				return
			}

			var encryptionkey []byte
			var encryptionKeyStr string

			timeStart := time.Now()
			res.DateReq = timeStart.Format("2006-01-02 15:04:05")
			encryptionkey = []byte(gf.GenerateRandomString(false, 32))
			encryptionKeyStr = base64.StdEncoding.EncodeToString(encryptionkey)
			if !gf.IsStringEmpty(&encryptionKeyStr) {
				res.TOTP, err = gf.GenerateBase64TOTP(encryptionKeyStr)
				if err != nil {
					res.ErrMsg = err.Error()
				} else {
					res.DateExp = timeStart.Add(30 * time.Second).Format("2006-01-02 15:04:05")
				}
			}
			json.NewEncoder(w).Encode(res)
		},
		Catch: func(e eh.Exception) {
			ex := fmt.Sprint(e)
			logger.Log(gf.GetFunctionName(GenerateOTP) + " " + ex)
		},
	}.Do()
}
