package repository

import (
	model_db "github.com/luthfikhan/go-simple-auth/model/db"
	"gorm.io/gorm"
)

type otpRepositoryImpl struct {
}

func NewOtpRepository() OtpRepository {
	return &otpRepositoryImpl{}
}

func (u *otpRepositoryImpl) InsertOtp(db *gorm.DB, otp *model_db.Otp) error {
	return db.Create(otp).Error
}

func (u *otpRepositoryImpl) DeleteOtp(db *gorm.DB, otp *model_db.Otp) error {
	if id := otp.Id; id == 0 {
		return db.Where("otp_id = ?", otp.OtpId).Delete(otp).Error
	}

	return db.Delete(otp).Error
}

func (u *otpRepositoryImpl) FindOtpById(db *gorm.DB, otpId string) (*model_db.Otp, error) {
	var otp model_db.Otp
	err := db.Where("otp_id = ?", otpId).First(&otp).Error
	if err != nil {
		return nil, err
	}

	return &otp, nil
}
