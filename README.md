## Golang Authentication Application
This application is an example implementation of authentication in Golang. The features provided include:

- New user registration
- User login
- Route protection with JWT token
- Refresh token
- Forgot password
#### Dependensi
- [Gin](https://gin-gonic.com/)
- [Gorm](https://gorm.io/) with [MySQL driver](https://pkg.go.dev/gorm.io/driver/mysql)
- [Golang JWT](https://github.com/golang-jwt/jwt)
- [Logrus](https://github.com/sirupsen/logrus) as a logger
#### Configuration
Fill the .env file with the following configuration:
```
# default 8080
PORT=
MYSQL_CONNECTION="user:pass@tcp(127.0.0.1:3306)/dbname?parseTime=true"
JWT_SECRET=secret
# smtp host
EMAIL_HOST=
EMAIL_PORT=
EMAIL_USERNAME=
EMAIL_PASSWORD=
EMAIL_FROM=mail@example.com
# in minutes
ACCESS_TOKEN_EXPIRED_TIME=30
REFRESH_TOKEN_EXPIRED_TIME=120
OTP_EXPIRED_TIME=5
```

