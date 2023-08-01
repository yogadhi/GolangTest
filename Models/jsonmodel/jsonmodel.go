package jsonmodel

// GenerateOTPReq struct
type GenerateOTPReq struct {
	DeviceID string `json:"DeviceID"`
}

// GenerateOTPRes struct
type GenerateOTPRes struct {
	TOTP    string `json:"TOTP"`
	DateReq string `json:"DateReq"`
	DateExp string `json:"DateExp"`
	ErrMsg  string `json:"ErrMsg"`
}
