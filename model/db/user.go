package model_db

type User struct {
	Id        int64  `gorm:"primaryKey;autoIncrement"`
	UpdatedAt int64  `gorm:"autoUpdateTime:milli"`
	CreatedAt int64  `gorm:"autoCreateTime:milli"`
	Email     string `gorm:"unique;not null"`
	Password  string
}
