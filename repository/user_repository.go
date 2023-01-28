package repository

import (
	model_db "github.com/luthfikhan/go-simple-auth/model/db"
	"gorm.io/gorm"
)

type UserRepository interface {
	FindUserByEmail(db *gorm.DB, email string) (*model_db.User, error)
	InsertUser(db *gorm.DB, user *model_db.User) error
	UpdateUser(db *gorm.DB, user *model_db.User) error
}
