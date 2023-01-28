package model_web

type AuthAuthidResponse struct {
	AuthId string `json:"auth_id"`
}

type AuthTokenResponse struct {
	AcessToken   string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
