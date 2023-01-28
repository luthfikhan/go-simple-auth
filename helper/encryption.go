package helper

import (
	"crypto/md5"
	"encoding/hex"
)

func GetMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func CheckPasswordHash(password, hash string) bool {
	return GetMD5Hash(password) == hash
}
