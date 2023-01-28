package model_web

import "net/http"

const (
	SuccessStatus             = "SUCCESS"
	BadRequestStatus          = "BAD_REQUEST"
	UnauthorizedStatus        = "UNAUTHORIZED"
	ForbiddenStatus           = "FORBIDDEN"
	NotFoundStatus            = "NOT_FOUND"
	InternalServerErrorStatus = "INTERNAL_SERVER_ERROR"

	EmailAlreadyRegisteredStatus = "EMAIL_ALREADY_REGISTERED"
	EmailNotRegisteredStatus     = "EMAIL_NOT_REGISTERED"
	InvalidOTPStatus             = "INVALID_OTP"
	ExpiredOTPStatus             = "EXPIRED_OTP"
	InvalidPasswordStatus        = "INVALID_PASSWORD"
)

type WebResponse[T any] struct {
	Status  string `json:"status"`
	Data    T      `json:"data,omitempty"`
	Code    uint   `json:"code"`
	Message string `json:"message,omitempty"`
}

var Success = &WebResponse[any]{
	Status: SuccessStatus,
	Code:   http.StatusOK,
}

var BadRequest = &WebResponse[any]{
	Status: BadRequestStatus,
	Code:   http.StatusBadRequest,
}

var Unauthorized = &WebResponse[any]{
	Status: UnauthorizedStatus,
	Code:   http.StatusUnauthorized,
}

var Forbidden = &WebResponse[any]{
	Status: ForbiddenStatus,
	Code:   http.StatusForbidden,
}

var NotFound = &WebResponse[any]{
	Status: NotFoundStatus,
	Code:   http.StatusNotFound,
}

var InternalServerError = &WebResponse[any]{
	Status: InternalServerErrorStatus,
	Code:   http.StatusInternalServerError,
}
