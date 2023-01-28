package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/luthfikhan/go-simple-auth/helper"
)

func Log(ctx *gin.Context) {
	now := time.Now()

	ctx.Next()

	helper.Log.Info(gin.H{
		"method":    ctx.Request.Method,
		"path":      ctx.Request.URL.Path,
		"query":     ctx.Request.URL.Query(),
		"code":      ctx.Writer.Status(),
		"timetaken": strconv.Itoa(int(time.Now().UnixMicro()-now.UnixMicro())) + " micro",
	})
}
