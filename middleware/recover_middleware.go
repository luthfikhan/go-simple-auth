package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luthfikhan/go-simple-auth/helper"
	model_web "github.com/luthfikhan/go-simple-auth/model/web"
)

func Recover() gin.HandlerFunc {
	return gin.CustomRecovery(func(ctx *gin.Context, err interface{}) {
		helper.Log.Error(gin.H{
			"error": err,
		}, "Recover from panic")
		ctx.JSON(http.StatusInternalServerError, model_web.InternalServerError)

		gin.RecoveryWithWriter(gin.DefaultErrorWriter)
	})
}
