package service

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/luthfikhan/go-simple-auth/helper"
	model_db "github.com/luthfikhan/go-simple-auth/model/db"
	model_web "github.com/luthfikhan/go-simple-auth/model/web"
	"github.com/luthfikhan/go-simple-auth/repository"
	"gorm.io/gorm"
)

type authServiceImpl struct {
	userRepository  repository.UserRepository
	db              *gorm.DB
	otpRepository   repository.OtpRepository
	tokenRepository repository.TokenRepository
}

func NewAuthService(
	userRepo repository.UserRepository,
	db *gorm.DB,
	otpRepo repository.OtpRepository,
	tokenRepository repository.TokenRepository,
) AuthService {
	return &authServiceImpl{
		userRepository:  userRepo,
		db:              db,
		otpRepository:   otpRepo,
		tokenRepository: tokenRepository,
	}
}

func (service authServiceImpl) Register(auth *model_web.AuthRegisterPayload) *model_web.WebResponse[any] {
	tx := service.db.Begin()
	defer helper.CheckErrorToCommitOrRollback(tx)

	auth.Password = helper.GetMD5Hash(auth.Password)
	if user, _ := service.userRepository.FindUserByEmail(service.db, auth.Email); user != nil {
		return &model_web.WebResponse[any]{
			Message: "Email already registered",
			Code:    http.StatusBadRequest,
			Status:  model_web.EmailAlreadyRegisteredStatus,
		}
	}
	otp, otpId := helper.GenerateOtpNumber(), auth.Email+"-otpid-"+strconv.Itoa(int(time.Now().UnixMilli()))
	tknData := helper.AuthIdTokenType{
		Email:     auth.Email,
		TokenType: helper.RegisterTokenType,
		OtpId:     otpId,
		Password:  auth.Password,
	}
	t, _ := strconv.Atoi(os.Getenv("OTP_EXPIRED_TIME"))
	ex := time.Now().Add(time.Duration(t) * time.Minute)
	tkn := helper.GenerataJwt(&tknData, &ex)

	helper.SendOtp(auth.Email, otp)
	service.otpRepository.InsertOtp(
		tx,
		&model_db.Otp{
			OtpId: otpId,
			Otp:   otp,
		},
	)

	return &model_web.WebResponse[any]{
		Status: model_web.SuccessStatus,
		Code:   http.StatusOK,
		Data: &model_web.AuthAuthidResponse{
			AuthId: tkn,
		},
	}
}
func (service authServiceImpl) ResendOTP(token, authorization *string) *model_web.WebResponse[any] {
	tx := service.db.Begin()
	defer helper.CheckErrorToCommitOrRollback(tx)
	tkn, _ := helper.ParseJwt[helper.AuthIdTokenType](*token)
	otp, otpId := helper.GenerateOtpNumber(), tkn.Email+"-otpid-"+strconv.Itoa(int(time.Now().UnixMilli()))

	helper.SendOtp(tkn.Email, otp)
	service.otpRepository.DeleteOtp(tx, &model_db.Otp{OtpId: tkn.OtpId})
	service.otpRepository.InsertOtp(
		tx,
		&model_db.Otp{
			OtpId: otpId,
			Otp:   otp,
		},
	)

	t, _ := strconv.Atoi(os.Getenv("OTP_EXPIRED_TIME"))
	ex := time.Now().Add(time.Duration(t) * time.Minute)
	tkn.OtpId = otpId
	newTkn := helper.GenerataJwt(&tkn, &ex)

	return &model_web.WebResponse[any]{
		Status: model_web.SuccessStatus,
		Code:   http.StatusOK,
		Data: &model_web.AuthAuthidResponse{
			AuthId: newTkn,
		},
	}
}

func (service authServiceImpl) ValidateOTP(payload *model_web.AuthOtpValidatePayload) *model_web.WebResponse[any] {
	tx := service.db.Begin()
	defer helper.CheckErrorToCommitOrRollback(tx)
	tkn, valid := helper.ParseJwt[helper.AuthIdTokenType](payload.AuthId)
	otp, _ := service.otpRepository.FindOtpById(tx, tkn.OtpId)

	if otp == nil || otp.Otp != payload.OTP {
		return &model_web.WebResponse[any]{
			Message: "Invalid OTP",
			Code:    http.StatusBadRequest,
			Status:  model_web.InvalidOTPStatus,
		}
	}
	service.otpRepository.DeleteOtp(tx, otp)

	if valid != nil && valid.Error() == helper.ExpiredTokenError {
		return &model_web.WebResponse[any]{
			Message: "Expired OTP",
			Code:    http.StatusBadRequest,
			Status:  model_web.ExpiredOTPStatus,
		}
	}

	if tkn.TokenType == helper.RegisterTokenType {
		service.userRepository.InsertUser(tx, &model_db.User{
			Email:    tkn.Email,
			Password: tkn.Password,
		})
	}

	if tkn.TokenType == helper.ForgotPasswordTokenType {
		t, _ := strconv.Atoi(os.Getenv("OTP_EXPIRED_TIME"))
		ex := time.Now().Add(time.Duration(t) * time.Minute)
		tkn.TokenType = helper.UpdatePasswordTokenType

		newTkn := helper.GenerataJwt(&tkn, &ex)

		return &model_web.WebResponse[any]{
			Status: model_web.SuccessStatus,
			Code:   http.StatusOK,
			Data: &model_web.AuthAuthidResponse{
				AuthId: newTkn,
			},
		}
	}

	if tkn.TokenType == helper.ChangePasswordTokenType {
		service.userRepository.UpdateUser(tx, &model_db.User{
			Email:    tkn.Email,
			Password: tkn.Password,
		})
	}

	accessToken, refreshToken, tokenId := helper.GenerateAccessToken(&tkn.Email)
	service.tokenRepository.InsertToken(tx, &model_db.Token{TokenId: tokenId})

	return &model_web.WebResponse[any]{
		Code:   http.StatusOK,
		Status: model_web.SuccessStatus,
		Data: &model_web.AuthTokenResponse{
			AcessToken:   accessToken,
			RefreshToken: refreshToken,
		},
	}
}

func (service authServiceImpl) Login(payload *model_web.AuthLoginPayload) (*model_web.WebResponse[any], bool) {
	tx := service.db.Begin()
	defer helper.CheckErrorToCommitOrRollback(tx)
	user, _ := service.userRepository.FindUserByEmail(tx, payload.Email)
	if user == nil {
		return &model_web.WebResponse[any]{
			Message: "User not found",
			Code:    http.StatusBadRequest,
			Status:  model_web.EmailNotRegisteredStatus,
		}, false
	}

	if !helper.CheckPasswordHash(payload.Password, user.Password) {
		return &model_web.WebResponse[any]{
			Message: "Invalid password",
			Code:    http.StatusBadRequest,
			Status:  model_web.InvalidPasswordStatus,
		}, false
	}

	if payload.TokenId == "" {
		otp, otpId := helper.GenerateOtpNumber(), payload.Email+"-otpid-"+strconv.Itoa(int(time.Now().UnixMilli()))
		tknData := helper.AuthIdTokenType{
			Email:     payload.Email,
			TokenType: helper.LoginTokenType,
			OtpId:     otpId,
		}
		t, _ := strconv.Atoi(os.Getenv("OTP_EXPIRED_TIME"))
		ex := time.Now().Add(time.Duration(t) * time.Minute)
		tkn := helper.GenerataJwt(&tknData, &ex)

		helper.SendOtp(payload.Email, otp)
		service.otpRepository.InsertOtp(
			tx,
			&model_db.Otp{
				OtpId: otpId,
				Otp:   otp,
			},
		)
		return &model_web.WebResponse[any]{
			Status: model_web.SuccessStatus,
			Code:   http.StatusOK,
			Data: &model_web.AuthAuthidResponse{
				AuthId: tkn,
			},
		}, false
	}

	accessToken, refreshToken, tokenId := helper.GenerateAccessToken(&payload.Email)
	service.tokenRepository.InsertToken(tx, &model_db.Token{TokenId: tokenId})

	return &model_web.WebResponse[any]{
		Code:   http.StatusOK,
		Status: model_web.SuccessStatus,
		Data: &model_web.AuthTokenResponse{
			AcessToken:   accessToken,
			RefreshToken: refreshToken,
		},
	}, true
}

func (service authServiceImpl) RefreshToken(payload *model_web.AuthRefreshTokenPayload) *model_web.WebResponse[any] {
	tx := service.db.Begin()
	defer helper.CheckErrorToCommitOrRollback(tx)
	refreshToken, valid := helper.ParseJwt[helper.AccessRefreshTokenType](payload.Token)
	accessToken := payload.AccesToken

	user, _ := service.userRepository.FindUserByEmail(tx, accessToken.Email)
	token, _ := service.tokenRepository.FindTokenById(tx, refreshToken.TokenId)

	if token == nil || (valid != nil && valid.Error() == helper.ExpiredTokenError) || refreshToken.Email != accessToken.Email || user == nil {
		return model_web.Unauthorized
	}

	service.tokenRepository.DeleteToken(tx, token)
	newAccessToken, newRefreshToken, tokenId := helper.GenerateAccessToken(&accessToken.Email)
	service.tokenRepository.InsertToken(tx, &model_db.Token{TokenId: tokenId})

	return &model_web.WebResponse[any]{
		Code:   http.StatusOK,
		Status: model_web.SuccessStatus,
		Data: &model_web.AuthTokenResponse{
			AcessToken:   newAccessToken,
			RefreshToken: newRefreshToken,
		},
	}
}

func (service authServiceImpl) Logout(token *string) *model_web.WebResponse[any] {
	tx := service.db.Begin()
	defer helper.CheckErrorToCommitOrRollback(tx)
	accessToken, _ := helper.ParseJwt[helper.AccessRefreshTokenType](*token)

	service.tokenRepository.DeleteToken(tx, &model_db.Token{TokenId: accessToken.TokenId})
	return model_web.Success
}

func (service authServiceImpl) ForgotPassword(payload *model_web.AuthForgotPasswordPayload) *model_web.WebResponse[any] {
	tx := service.db.Begin()
	defer helper.CheckErrorToCommitOrRollback(tx)
	user, _ := service.userRepository.FindUserByEmail(tx, payload.Email)
	if user == nil {
		return &model_web.WebResponse[any]{
			Message: "User not found",
			Code:    http.StatusBadRequest,
			Status:  model_web.EmailNotRegisteredStatus,
		}
	}

	otp, otpId := helper.GenerateOtpNumber(), payload.Email+"-otpid-"+strconv.Itoa(int(time.Now().UnixMilli()))
	tknData := helper.AuthIdTokenType{
		Email:     payload.Email,
		TokenType: helper.ForgotPasswordTokenType,
		OtpId:     otpId,
	}
	t, _ := strconv.Atoi(os.Getenv("OTP_EXPIRED_TIME"))
	ex := time.Now().Add(time.Duration(t) * time.Minute)
	tkn := helper.GenerataJwt(&tknData, &ex)
	helper.SendOtp(payload.Email, otp)
	service.otpRepository.InsertOtp(
		tx,
		&model_db.Otp{
			OtpId: otpId,
			Otp:   otp,
		},
	)

	return &model_web.WebResponse[any]{
		Status: model_web.SuccessStatus,
		Code:   http.StatusOK,
		Data: &model_web.AuthAuthidResponse{
			AuthId: tkn,
		},
	}
}

func (service authServiceImpl) ChangePassword(payload *model_web.AuthChangePasswordPayload) *model_web.WebResponse[any] {
	tx := service.db.Begin()
	defer helper.CheckErrorToCommitOrRollback(tx)

	if payload.AuthId == "" {
		user, _ := service.userRepository.FindUserByEmail(tx, payload.AccesToken.Email)
		payload.NewPassword = helper.GetMD5Hash(payload.NewPassword)

		if user == nil {
			return &model_web.WebResponse[any]{
				Code:    http.StatusBadRequest,
				Message: "User not found",
				Status:  model_web.EmailNotRegisteredStatus,
			}
		}

		if user.Password != helper.GetMD5Hash(payload.OldPassword) {
			return &model_web.WebResponse[any]{
				Code:    http.StatusBadRequest,
				Message: "Invalid password",
				Status:  model_web.InvalidPasswordStatus,
			}
		}

		otp, otpId := helper.GenerateOtpNumber(), payload.AccesToken.Email+"-otpid-"+strconv.Itoa(int(time.Now().UnixMilli()))
		tknData := helper.AuthIdTokenType{
			Email:     payload.AccesToken.Email,
			TokenType: helper.ChangePasswordTokenType,
			OtpId:     otpId,
			Password:  payload.NewPassword,
		}
		t, _ := strconv.Atoi(os.Getenv("OTP_EXPIRED_TIME"))
		ex := time.Now().Add(time.Duration(t) * time.Minute)
		tkn := helper.GenerataJwt(&tknData, &ex)

		helper.SendOtp(payload.AccesToken.Email, otp)
		service.otpRepository.InsertOtp(
			tx,
			&model_db.Otp{
				OtpId: otpId,
				Otp:   otp,
			},
		)

		return &model_web.WebResponse[any]{
			Status: model_web.SuccessStatus,
			Code:   http.StatusOK,
			Data: &model_web.AuthAuthidResponse{
				AuthId: tkn,
			},
		}
	}
	authId, _ := helper.ParseJwt[helper.AuthIdTokenType](payload.AuthId)
	user, _ := service.userRepository.FindUserByEmail(tx, authId.Email)

	if user == nil {
		return &model_web.WebResponse[any]{
			Code:    http.StatusBadRequest,
			Message: "User not found",
			Status:  model_web.EmailNotRegisteredStatus,
		}
	}
	user.Password = helper.GetMD5Hash(payload.NewPassword)
	service.userRepository.UpdateUser(tx, user)

	return model_web.Success
}

func (service authServiceImpl) ChangeEmail(payload *model_web.AuthChangeEmailPayload) *model_web.WebResponse[any] {
	return &model_web.WebResponse[any]{}
}
