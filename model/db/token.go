package model_db

type Token struct {
	TokenId string `gorm:"unique"`
	Id      uint   `gorm:"primaryKey"`
}
