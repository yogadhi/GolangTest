package jsonmodel

type Configuration struct {
	SignatureKey   string `json:"SignatureKey"`
	TOTPDigitCount int    `json:"TOTPDigitCount"`
	TOTPDuration   int    `json:"TOTPDuration"`
	Port           string `json:"Port"`
	TLSPort        string `json:"TLSPort"`
}
type GenerateOTPReq struct {
	DeviceID string `json:"DeviceID"`
}

type GenerateOTPRes struct {
	TOTP    string `json:"TOTP"`
	DateReq string `json:"DateReq"`
	DateExp string `json:"DateExp"`
	ErrMsg  string `json:"ErrMsg"`
}

type ValidateOTPReq struct {
	TOTP string `json:"TOTP"`
	// DeviceID string `json:"DeviceID"`
}

type ValidateOTPRes struct {
	IsTOTPValid bool   `json:"IsValid"`
	ErrMsg      string `json:"ErrMsg"`
}

type Token struct {
	SecretKey string `json:"SecretKey"`
	UserID    string `json:"UserID"`
	DeviceID  string `json:"DeviceID"`
	RegDate   string `json:"RegDate"`
	ExpDate   string `json:"ExpDate"`
}

type GoEncryptReq struct {
	Key       string `json:"Key"`
	PlainText string `json:"PlainText"`
}

type GoEncryptRes struct {
	EncryptedText string `json:"EncryptedText"`
}

type GoDecryptReq struct {
	Key           string `json:"Key"`
	EncryptedText string `json:"EncryptedText"`
}

type GoDecryptRes struct {
	DecryptedText string `json:"DecryptedText"`
}
