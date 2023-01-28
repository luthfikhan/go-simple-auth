package helper

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	RefreshTokenType        = "refresh_token"
	AccessTokenType         = "access_token"
	UpdatePasswordTokenType = "update_password_token"
	RegisterTokenType       = "otp_register_token"
	LoginTokenType          = "otp_login_token"
	ForgotPasswordTokenType = "otp_forgot_password_token"
	ChangeEmailTokenType    = "otp_change_email_token"
	ChangePasswordTokenType = "otp_change_password_token"

	ExpiredTokenError = "expired_token"
)

type JwtClaims[T any] struct {
	Data T `json:"data"`
	jwt.RegisteredClaims
}

type AuthIdTokenType struct {
	Email     string `json:"email"`
	TokenType string `json:"token_type"`
	Password  string `json:"password,omitempty"`
	OtpId     string `json:"otp_id"`
}

type AccessRefreshTokenType struct {
	Email     string `json:"email"`
	TokenType string `json:"token_type"`
	TokenId   string `json:"token_id"`
}

func TokenExtractor(auth *string) string {
	tokenExtractor := regexp.MustCompile(`[Bb]earer\s+(.*)`)
	*auth = tokenExtractor.ReplaceAllString(*auth, "$1")

	return *auth
}

func GenerataJwt[T any](data *T, expiredIn *time.Time) string {
	var JWTSecret = []byte(os.Getenv("JWT_SECRET"))

	claims := JwtClaims[T]{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(*expiredIn),
		},
		Data: *data,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(JWTSecret)
	PanicIfError(err)

	return signedToken
}

func ParseJwt[T any](token string) (T, error) {
	var JWTSecret = []byte(os.Getenv("JWT_SECRET"))
	claims := JwtClaims[T]{}
	parsedToken, err := jwt.ParseWithClaims(token, &claims, func(_ *jwt.Token) (interface{}, error) {
		return JWTSecret, nil
	})
	if err == nil && parsedToken.Valid {
		return claims.Data, nil
	}

	if strings.Contains(err.Error(), jwt.ErrTokenExpired.Error()) {
		return claims.Data, errors.New(ExpiredTokenError)
	}

	panic(err)
}

func GenerateAccessToken(email *string) (accessToken, refreshToken, tokenId string) {
	now := time.Now()
	rTknExpTime, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRED_TIME"))
	aTknExpTime, _ := strconv.Atoi(os.Getenv("ACCESS_TOKEN_EXPIRED_TIME"))
	exRTkn := now.Add(time.Duration(rTknExpTime) * time.Minute)
	exATkn := now.Add(time.Duration(aTknExpTime) * time.Minute)
	token := AccessRefreshTokenType{
		Email:     *email,
		TokenType: AccessTokenType,
		TokenId:   *email + "-tokenid-" + strconv.Itoa(int(now.UnixMilli())),
	}
	accessToken = GenerataJwt(&token, &exATkn)
	token.TokenType = RefreshTokenType
	refreshToken = GenerataJwt(&token, &exRTkn)
	tokenId = token.TokenId

	return
}
