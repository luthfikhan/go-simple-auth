package app

import (
	"os"

	model_db "github.com/luthfikhan/go-simple-auth/model/db"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func NewMySQL() *gorm.DB {
	conn := os.Getenv("MYSQL_CONNECTION")
	db, err := gorm.Open(mysql.Open(conn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	db.AutoMigrate(&model_db.User{}, &model_db.Token{}, &model_db.Otp{})

	return db
}
