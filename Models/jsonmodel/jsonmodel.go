package jsonmodel

type Configuration struct {
	SignatureKey   string `json:"SignatureKey"`
	TOTPDigitCount int
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
	UserID   string `json:"UserID"`
	DeviceID string `json:"DeviceID"`
	RegDate  string `json:"RegDate"`
	ExpDate  string `json:"ExpDate"`
}
