package model_web

import (
	"github.com/luthfikhan/go-simple-auth/helper"
)

type AuthRegisterPayload struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=32"`
}

type AuthOtpValidatePayload struct {
	AccesToken helper.AccessRefreshTokenType
	OTP        string `json:"otp" binding:"required"`
	AuthId     string `json:"auth_id" binding:"required"`
}

type AuthLoginPayload struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=32"`
	TokenId  string
}

type AuthRefreshTokenPayload struct {
	AccesToken helper.AccessRefreshTokenType
	Token      string `json:"token" binding:"required"`
}

type AuthForgotPasswordPayload struct {
	Email string `json:"email" binding:"required,email"`
}

type AuthChangePasswordPayload struct {
	AccesToken  helper.AccessRefreshTokenType
	AuthId      string `json:"auth_id"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=32"`
	OldPassword string `json:"old_password" binding:"required,min=8,max=32"`
}
type AuthChangeForgottenPasswordPayload struct {
	AuthId      string `json:"auth_id"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=32"`
}

type AuthChangeEmailPayload struct {
	AccesToken helper.AccessRefreshTokenType
	Email      string `json:"email" binding:"required,email"`
}
