package repository

import (
	model_db "github.com/luthfikhan/go-simple-auth/model/db"
	"gorm.io/gorm"
)

type TokenRepository interface {
	InsertToken(db *gorm.DB, token *model_db.Token) error
	DeleteToken(db *gorm.DB, token *model_db.Token) error
	FindTokenById(db *gorm.DB, tokenId string) (*model_db.Token, error)
}
