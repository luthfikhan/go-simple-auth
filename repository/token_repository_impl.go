package repository

import (
	model_db "github.com/luthfikhan/go-simple-auth/model/db"
	"gorm.io/gorm"
)

type tokenRepositoryImpl struct {
}

func NewTokenRepository() TokenRepository {
	return &tokenRepositoryImpl{}
}

func (u *tokenRepositoryImpl) InsertToken(db *gorm.DB, token *model_db.Token) error {
	return db.Create(token).Error
}

func (u *tokenRepositoryImpl) DeleteToken(db *gorm.DB, token *model_db.Token) error {
	if id := token.Id; id == 0 {
		return db.Where("token_id = ?", token.TokenId).Delete(token).Error
	}

	return db.Delete(token).Error
}

func (u *tokenRepositoryImpl) FindTokenById(db *gorm.DB, tokenId string) (*model_db.Token, error) {
	var token model_db.Token
	err := db.Where("token_id = ?", tokenId).First(&token).Error
	if err != nil {
		return nil, err
	}

	return &token, nil
}
