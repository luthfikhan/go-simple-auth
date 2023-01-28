package repository

import (
	model_db "github.com/luthfikhan/go-simple-auth/model/db"
	"gorm.io/gorm"
)

type userRepositoryImpl struct {
}

func NewUserRepository() UserRepository {
	return &userRepositoryImpl{}
}

func (u *userRepositoryImpl) FindUserByEmail(db *gorm.DB, email string) (*model_db.User, error) {
	var user model_db.User

	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

func (u *userRepositoryImpl) InsertUser(db *gorm.DB, user *model_db.User) error {
	return db.Create(user).Error
}

func (u *userRepositoryImpl) UpdateUser(db *gorm.DB, user *model_db.User) error {
	return db.Save(user).Error
}
