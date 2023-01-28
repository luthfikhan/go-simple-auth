package controller

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/luthfikhan/go-simple-auth/helper"
	model_web "github.com/luthfikhan/go-simple-auth/model/web"
	"github.com/luthfikhan/go-simple-auth/service"
)

type authControllerImpl struct {
	authService service.AuthService
}

func NewAuthController(service service.AuthService) AuthController {
	return &authControllerImpl{
		authService: service,
	}
}

func (ctrl authControllerImpl) Register(ctx *gin.Context) {
	payload := model_web.AuthRegisterPayload{}
	if err := ctx.ShouldBindJSON(&payload); err == nil {
		response := ctrl.authService.Register(&payload)
		ctx.JSON(int(response.Code), response)
	} else {
		ctx.JSON(400, model_web.WebResponse[any]{
			Message: err.Error(),
			Code:    http.StatusBadRequest,
			Status:  model_web.BadRequestStatus,
		})
	}
}

func (ctrl authControllerImpl) ResendOTP(ctx *gin.Context) {
	if authId := ctx.Query("auth_id"); authId != "" {
		authorization := ctx.GetHeader("Authorization")
		helper.TokenExtractor(&authorization)

		response := ctrl.authService.ResendOTP(&authId, &authorization)
		ctx.JSON(int(response.Code), response)
	} else {
		ctx.JSON(400, model_web.WebResponse[any]{
			Message: "auth_id is required",
			Code:    http.StatusBadRequest,
			Status:  model_web.BadRequestStatus,
		})
	}
}

func (ctrl authControllerImpl) ValidateOTP(ctx *gin.Context) {
	payload := model_web.AuthOtpValidatePayload{}
	if err := ctx.ShouldBindJSON(&payload); err == nil {
		authorization := ctx.GetHeader("Authorization")
		helper.TokenExtractor(&authorization)

		if authorization != "" {
			accessToken, _ := helper.ParseJwt[helper.AccessRefreshTokenType](authorization)

			payload.AccesToken = accessToken
		}

		response := ctrl.authService.ValidateOTP(&payload)
		if response.Code == http.StatusOK {
			authId, _ := helper.ParseJwt[helper.AuthIdTokenType](payload.AuthId)

			setTokenCookie(ctx, &authId.Email)
		}
		ctx.JSON(int(response.Code), response)
	} else {
		ctx.JSON(400, model_web.WebResponse[any]{
			Message: err.Error(),
			Code:    http.StatusBadRequest,
			Status:  model_web.BadRequestStatus,
		})
	}
}

func (ctrl authControllerImpl) Login(ctx *gin.Context) {
	payload := model_web.AuthLoginPayload{}
	if err := ctx.ShouldBindJSON(&payload); err == nil {
		tokenIdCookie, _ := ctx.Cookie("x-tokenid")

		payload.TokenId = tokenIdCookie
		response, setCookie := ctrl.authService.Login(&payload)

		if setCookie {
			setTokenCookie(ctx, &payload.Email)
		}
		ctx.JSON(int(response.Code), response)
	} else {
		ctx.JSON(400, model_web.WebResponse[any]{
			Message: err.Error(),
			Code:    http.StatusBadRequest,
			Status:  model_web.BadRequestStatus,
		})
	}
}

func (ctrl authControllerImpl) RefreshToken(ctx *gin.Context) {
	payload := model_web.AuthRefreshTokenPayload{}
	if err := ctx.ShouldBindJSON(&payload); err == nil {
		authorization := ctx.GetHeader("Authorization")
		helper.TokenExtractor(&authorization)
		accessToken, _ := helper.ParseJwt[helper.AccessRefreshTokenType](authorization)

		payload.AccesToken = accessToken

		response := ctrl.authService.RefreshToken(&payload)
		if response.Code == http.StatusOK {
			setTokenCookie(ctx, &accessToken.Email)
		}
		ctx.JSON(int(response.Code), response)
	} else {
		ctx.JSON(400, model_web.WebResponse[any]{
			Message: err.Error(),
			Code:    http.StatusBadRequest,
			Status:  model_web.BadRequestStatus,
		})
	}
}

func (ctrl authControllerImpl) Logout(ctx *gin.Context) {
	authorization := ctx.GetHeader("Authorization")
	helper.TokenExtractor(&authorization)

	if authorization != "" {
		response := ctrl.authService.Logout(&authorization)
		ctx.JSON(int(response.Code), response)
	} else {
		ctx.JSON(400, model_web.WebResponse[any]{
			Message: "Authorization header is required",
			Code:    http.StatusBadRequest,
			Status:  model_web.BadRequestStatus,
		})
	}
}

func (ctrl authControllerImpl) ForgotPassword(ctx *gin.Context) {
	payload := model_web.AuthForgotPasswordPayload{}
	if err := ctx.ShouldBindJSON(&payload); err == nil {
		response := ctrl.authService.ForgotPassword(&payload)
		ctx.JSON(int(response.Code), response)
	} else {
		ctx.JSON(400, model_web.WebResponse[any]{
			Message: err.Error(),
			Code:    http.StatusBadRequest,
			Status:  model_web.BadRequestStatus,
		})
	}
}

func (ctrl authControllerImpl) ChangePassword(ctx *gin.Context) {
	payload := &model_web.AuthChangePasswordPayload{}
	p := &model_web.AuthChangeForgottenPasswordPayload{}

	badRequest := func(err error) {
		ctx.JSON(400, model_web.WebResponse[any]{
			Message: err.Error(),
			Code:    http.StatusBadRequest,
			Status:  model_web.BadRequestStatus,
		})
	}

	prosses := func() {
		authorization := ctx.GetHeader("Authorization")
		helper.TokenExtractor(&authorization)

		if authorization != "" {
			accessToken, valid := helper.ParseJwt[helper.AccessRefreshTokenType](authorization)

			if payload.AuthId == "" && valid != nil && valid.Error() == helper.ExpiredTokenError {
				ctx.JSON(401, model_web.WebResponse[any]{
					Code:   http.StatusUnauthorized,
					Status: model_web.UnauthorizedStatus,
				})
				return
			}

			payload.AccesToken = accessToken
		}

		response := ctrl.authService.ChangePassword(payload)
		ctx.JSON(int(response.Code), response)
	}

	if err := ctx.ShouldBindBodyWith(&p, binding.JSON); err == nil {
		if p.AuthId == "" {
			if err := ctx.ShouldBindBodyWith(&payload, binding.JSON); err == nil {
				prosses()
			} else {
				badRequest(err)
			}
		} else {
			payload = &model_web.AuthChangePasswordPayload{
				AuthId:      p.AuthId,
				NewPassword: p.NewPassword,
			}
			prosses()
		}
	} else {
		badRequest(err)
	}
}

func (ctrl authControllerImpl) ChangeEmail(ctx *gin.Context) {

}

func setTokenCookie(ctx *gin.Context, email *string) {
	cookieLifeTime := 7 * 24 * 60 * 60
	jwtLifeTime := time.Now().Add(time.Second * time.Duration(cookieLifeTime))
	tokenCookie := helper.GenerataJwt(email, &jwtLifeTime)

	ctx.SetCookie("x-tokenid", tokenCookie, cookieLifeTime, "/", "", false, true)
}
