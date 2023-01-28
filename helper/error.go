package helper

import "gorm.io/gorm"

func PanicIfError(err error) {
	if err != nil {
		panic(err)
	}
}

func CheckErrorToCommitOrRollback(tx *gorm.DB) {
	if r := recover(); r != nil {
		tx.Rollback()
	} else {
		tx.Commit()
	}
}
