package helper

import (
	"bytes"
	"fmt"
	"html/template"
	"time"

	"github.com/luthfikhan/go-simple-auth/app"
)

func GenerateOtpNumber() string {

	return fmt.Sprint(time.Now().Nanosecond())[:6]
}

func SendOtp(email, otp string) {
	go func() {
		t := template.Must(template.ParseFiles("assets/otp.gohtml"))

		var tpl bytes.Buffer
		t.Execute(&tpl, otp)

		mailer := app.Mailer{
			To:      email,
			Subject: "OTP Verification",
			Body:    tpl.String(),
		}
		mailer.Send()
	}()
}
