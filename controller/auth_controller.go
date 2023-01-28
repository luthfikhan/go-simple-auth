package controller

import "github.com/gin-gonic/gin"

type AuthController interface {
	Register(ctx *gin.Context)
	ResendOTP(ctx *gin.Context)
	ValidateOTP(ctx *gin.Context)
	Login(ctx *gin.Context)
	RefreshToken(ctx *gin.Context)
	Logout(ctx *gin.Context)
	ForgotPassword(ctx *gin.Context)
	ChangePassword(ctx *gin.Context)
	ChangeEmail(ctx *gin.Context)
}
