package service

import (
	model_web "github.com/luthfikhan/go-simple-auth/model/web"
)

type AuthService interface {
	Register(auth *model_web.AuthRegisterPayload) *model_web.WebResponse[any]
	ResendOTP(authId, authorization *string) *model_web.WebResponse[any]
	ValidateOTP(payload *model_web.AuthOtpValidatePayload) *model_web.WebResponse[any]
	Login(payload *model_web.AuthLoginPayload) (*model_web.WebResponse[any], bool)
	RefreshToken(payload *model_web.AuthRefreshTokenPayload) *model_web.WebResponse[any]
	Logout(token *string) *model_web.WebResponse[any]
	ForgotPassword(payload *model_web.AuthForgotPasswordPayload) *model_web.WebResponse[any]
	ChangePassword(payload *model_web.AuthChangePasswordPayload) *model_web.WebResponse[any]
	ChangeEmail(payload *model_web.AuthChangeEmailPayload) *model_web.WebResponse[any]
}
