package app

import (
	"crypto/tls"
	"os"
	"strconv"

	"gopkg.in/gomail.v2"
)

type Mailer struct {
	To         string
	Subject    string
	Body       string
	Attachment string
}

func (m *Mailer) Send() {
	var (
		EmailHost     = os.Getenv("EMAIL_HOST")
		EmailPort     = os.Getenv("EMAIL_PORT")
		EmailUsername = os.Getenv("EMAIL_USERNAME")
		EmailPassword = os.Getenv("EMAIL_PASSWORD")
		EmailFrom     = os.Getenv("EMAIL_FROM")
	)

	mail := gomail.NewMessage()
	mail.SetHeader("From", EmailFrom)
	mail.SetHeader("To", m.To)
	mail.SetHeader("Subject", m.Subject)
	mail.SetBody("text/html", m.Body)

	if m.Attachment != "" {
		mail.Attach(m.Attachment)
	}

	port, _ := strconv.Atoi(EmailPort)

	d := gomail.NewDialer(EmailHost, port, EmailUsername, EmailPassword)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	err := d.DialAndSend(mail)

	if err != nil {
		panic(err)
	}
}
