package model_db

type Otp struct {
	Id    int    `gorm:"primaryKey;autoIncrement;not null"`
	OtpId string `gorm:"unique;not null"`
	Otp   string `gorm:"not null"`
}
