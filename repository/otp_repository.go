package repository

import (
	model_db "github.com/luthfikhan/go-simple-auth/model/db"
	"gorm.io/gorm"
)

type OtpRepository interface {
	InsertOtp(db *gorm.DB, otp *model_db.Otp) error
	DeleteOtp(db *gorm.DB, otp *model_db.Otp) error
	FindOtpById(db *gorm.DB, otpId string) (*model_db.Otp, error)
}
