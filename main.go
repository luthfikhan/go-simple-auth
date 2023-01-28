package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/luthfikhan/go-simple-auth/app"
	"github.com/luthfikhan/go-simple-auth/controller"
	"github.com/luthfikhan/go-simple-auth/helper"
	"github.com/luthfikhan/go-simple-auth/middleware"
	model_web "github.com/luthfikhan/go-simple-auth/model/web"
	"github.com/luthfikhan/go-simple-auth/repository"
	"github.com/luthfikhan/go-simple-auth/service"
	"github.com/sirupsen/logrus"
)

func init() {
	logrus.SetFormatter(&logrus.JSONFormatter{})

	err := godotenv.Load()
	if err != nil {
		helper.Log.Error(nil, err)
	}
}

func main() {
	router := gin.New()
	router.Use(middleware.Log, middleware.Recover())
	router.NoRoute(func(ctx *gin.Context) {
		ctx.JSON(http.StatusNotFound, model_web.NotFound)
	})

	db := app.NewMySQL()
	userRepository := repository.NewUserRepository()
	otpRepository := repository.NewOtpRepository()
	tokenRepository := repository.NewTokenRepository()
	authService := service.NewAuthService(userRepository, db, otpRepository, tokenRepository)
	authCtrl := controller.NewAuthController(authService)

	authRouter := router.Group("/api/auth")
	authRouter.POST("/signup", authCtrl.Register)
	authRouter.POST("/otp", authCtrl.ValidateOTP)
	authRouter.GET("/otp", authCtrl.ResendOTP)
	authRouter.POST("/refresh-token", authCtrl.RefreshToken)
	authRouter.POST("/login", authCtrl.Login)
	authRouter.GET("/logout", authCtrl.Logout)
	authRouter.POST("/password", authCtrl.ForgotPassword)
	authRouter.PUT("/password", authCtrl.ChangePassword)

	authRouterWithAccessToken := router.Group("/api/auth")
	// authRouterWithAccessToken.Use(middleware.VerifyAccessToken)
	authRouterWithAccessToken.PUT("/email", authCtrl.ChangeEmail)

	router.Run()
}
