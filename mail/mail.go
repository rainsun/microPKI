package mail

import (
	"net/smtp"
	"log"
	"github.com/scorredoira/email"
	"net/mail"
)

func SendMail(to string, subj string, msg string, attachment string) error {
	// Set up authentication information.
	auth := smtp.PlainAuth("", "notify", "", "localhost")


	m := email.NewMessage(subj, msg)
	m.From = mail.Address{Name: "Infrastructure Team", Address: "no-reply@domain.com"}
	m.To = []string{to}

	var err error
	if attachment != "" {
		err = m.Attach(attachment)
		if err != nil {
			log.Println(err)
		}
	}

	return email.Send("localhost:25", auth, m)
}
