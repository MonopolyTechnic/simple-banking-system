package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/smtp"

	"github.com/flosch/pongo2/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

// Wrapper func to read the env file while only returning the map
func readEnv(filepath string) map[string]string {
	env, err := godotenv.Read(filepath)
	handle(err)
	return env
}

// Helper func that acts as a context manager to open a new connection to the database
func OpenDBConnection(fn func(conn *pgxpool.Pool) error) error {
	url := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", env["DB_USERNAME"], env["DB_PASSWORD"], env["DB_HOST"], env["DB_PORT"], env["DB_NAME"])
	conn, err := pgxpool.New(context.Background(), url)
	if err != nil {
		return err
	}
	defer conn.Close()
	return fn(conn)
}

// Helper function to render a template
func RenderTemplate(w http.ResponseWriter, filename string, ctx ...pongo2.Context) {
	tpl, err := pongo2.FromFile("./templates/" + filename)
	handle(err)

	var context pongo2.Context
	if len(ctx) == 0 {
		context = pongo2.Context{}
	} else if len(ctx) == 1 {
		context = ctx[0]
	} else {
		context = ctx[0]
		for i, c := range ctx {
			if i == 0 {
				continue
			}
			context.Update(c)
		}
	}

	err = tpl.ExecuteWriter(context, w)
	if err != nil {
		log.Println("Error rendering template:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Helper func to retrieve flashes
func RetrieveFlashes(r *http.Request, w http.ResponseWriter) []interface{} {
	session, err := store.Get(r, "session-name")
	handle(err)

	flashes := session.Flashes()
	session.Save(r, w)
	return flashes
}

// Helper function to send a verification code to a phone number given the carrier
func SendCode(phoneNumber, phoneCarrier string) (int, error) {
	emailSender = env["EMAIL_SENDER"] // Read email sender from environment
	emailPassword = env["EMAIL_PASSWORD"]

	// Look up carrier gateway
	carrierGateway, exists := smsGateways[phoneCarrier]
	if !exists {
		return 0, fmt.Errorf("unsupported carrier: %s", phoneCarrier)
	}

	recipientSMS := fmt.Sprintf("%s@%s", phoneNumber, carrierGateway)

	// Generate a random 6-digit verification code
	verificationCode := rand.Intn(900000) + 100000

	// Create the plain-text message body
	message := fmt.Sprintf("Subject: Verification Code\n\nYour verification code is: %d", verificationCode)

	// Set up SMTP connection
	conn, err := net.Dial("tcp", "smtp.gmail.com:587")
	if err != nil {
		return 0, fmt.Errorf("could not connect to SMTP server: %v", err)
	}

	// Create SMTP client
	host := "smtp.gmail.com"
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return 0, fmt.Errorf("could not create SMTP client: %v", err)
	}

	// Upgrade to TLS
	tlsConfig := &tls.Config{
		ServerName: host,
	}
	if err := c.StartTLS(tlsConfig); err != nil {
		return 0, fmt.Errorf("could not start TLS: %v", err)
	}

	// Authenticate using AUTH LOGIN
	auth := LoginAuth(emailSender, emailPassword)
	if err := c.Auth(auth); err != nil {
		return 0, fmt.Errorf("could not authenticate: %v", err)
	}

	// Set the sender and recipient
	if err := c.Mail(emailSender); err != nil {
		return 0, fmt.Errorf("could not set sender: %v", err)
	}
	if err := c.Rcpt(recipientSMS); err != nil {
		return 0, fmt.Errorf("could not set recipient: %v", err)
	}

	// Send the email
	w, err := c.Data()
	if err != nil {
		return 0, fmt.Errorf("could not send data: %v", err)
	}
	if _, err := w.Write([]byte(message)); err != nil {
		return 0, fmt.Errorf("could not write to SMTP: %v", err)
	}
	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("could not close SMTP connection: %v", err)
	}

	c.Quit()

	// Return the verification code to the caller
	return verificationCode, nil
}

// Define AUTH LOGIN
type loginAuth struct {
	username, password string
}

func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte(a.username), nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, errors.New("unknown from server")
		}
	}
	return nil, nil
}

// Helper func to handle errors
func handle(err error, fmtStr ...string) {
	fmt := fmt.Sprintf("%v\n", err)
	if len(fmtStr) >= 1 {
		fmt = fmtStr[0] + ": " + fmt
	}
	if err != nil {
		log.Fatal(fmt)
	}
}
