package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/smtp"
	"regexp"
	"strings"
	"time"

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

func capitalizeFilter(value *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
	// Ensure the value is a string
	if str, ok := value.Interface().(string); ok {
		// Capitalize the first letter and return the value
		if len(str) > 0 {
			return pongo2.AsValue(strings.ToUpper(string(str[0])) + str[1:]), nil
		}
	}
	// If it's not a string, return it as is
	return pongo2.AsValue(value.Interface()), nil
}

func formatBalance(value *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
	// Ensure the value is a float64
	if balance, ok := value.Interface().(float64); ok {
		// Format the float to two decimal places
		formattedBalance := fmt.Sprintf("%.2f", balance)
		return pongo2.AsValue(formattedBalance), nil
	}
	// Return an error if the value is not a float64
	return pongo2.AsValue(0), nil
}

func stripNonAlphanumeric(input string) string {
	// Create a regular expression to match non-alphanumeric characters
	re := regexp.MustCompile("[^a-zA-Z0-9]")

	// Replace all non-alphanumeric characters with an empty string
	return re.ReplaceAllString(input, "")
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

// Helper function to add a flash message to the flash session
func AddFlash(r *http.Request, w http.ResponseWriter, msg string) {
	flashSession, err2 := store.Get(r, "flash-session")
	handle(err2)

	flashSession.AddFlash(msg)
	err2 = flashSession.Save(r, w)
	handle(err2)
}

// Helper func to retrieve flashes
func RetrieveFlashes(r *http.Request, w http.ResponseWriter) []interface{} {
	session, err := store.Get(r, "flash-session")
	handle(err)

	flashes := session.Flashes()
	session.Save(r, w)
	return flashes
}

// flash is expected to be a string type
// flash is defined as "s{msg}" , or "e{msg}" where the first character denotes success or error
// and the rest of the string is the flash message
func getFlashType(value *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
	if str, ok := value.Interface().(string); ok {
		if len(str) < 1 {
			handle(errors.New("Flash message is empty"))
		}
		var flashType string = string(str[0]) //only handles ascii
		if flashType == "s" {
			return pongo2.AsValue("success"), nil
		} else if flashType == "e" {
			return pongo2.AsValue("error"), nil
		} else {
			handle(errors.New("Flash message is not of the correct format , start character should be 's' or 'e'"))
		}
	}
	handle(errors.New("Flash message is not of the correct format , message should be a string"))
	log.Println("should never print this utils.getFlashType")
	return pongo2.AsValue("will never reach here"), nil
}

func getFlashMessage(value *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
	if str, ok := value.Interface().(string); ok {
		if len(str) < 1 {
			handle(errors.New("Flash message is empty"))
		}
		var flashMessage string = str[1:]
		return pongo2.AsValue(flashMessage), nil
	}
	handle(errors.New("Flash message is not of the correct format , message should be a string"))
	log.Println("should never print this utils.getFlashMessage")
	return pongo2.AsValue("will never reach here"), nil
}

func generateResetToken() string {
	// Generate a random token (you could use a stronger method, like UUID or a hash)
	rand.Seed(time.Now().UnixNano())
	const tokenLength = 32
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var token []byte
	for i := 0; i < tokenLength; i++ {
		token = append(token, charset[rand.Intn(len(charset))])
	}
	return string(token)
}

// Returns email, true if the token is valid, otherwise returns "", false
func isValidToken(w http.ResponseWriter, r *http.Request, token string) (string, bool) {
	// Check if the token exists
	session, err := store.Get(r, "reset-password-session")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return "", false
	}
	val, exists := session.Values[token]
	var email string
	if val != nil {
		email = val.(string)
	} else {
		email = ""
	}
	return email, exists
}

func SendEmail(endemail string, subject string, body string) error {
	emailSender = env["EMAIL_SENDER"] // Read email sender from environment
	emailPassword = env["EMAIL_PASSWORD"]

	// Create the plain-text message body
	message := fmt.Sprintf("Subject: %s\n\n%s: %d", subject, body)

	// Set up SMTP connection
	conn, err := net.Dial("tcp", "smtp.gmail.com:587")
	if err != nil {
		return fmt.Errorf("could not connect to SMTP server: %v", err)
	}

	// Create SMTP client
	host := "smtp.gmail.com"
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("could not create SMTP client: %v", err)
	}

	// Upgrade to TLS
	tlsConfig := &tls.Config{
		ServerName: host,
	}
	if err := c.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("could not start TLS: %v", err)
	}

	// Authenticate using AUTH LOGIN
	auth := LoginAuth(emailSender, emailPassword)
	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("could not authenticate: %v", err)
	}

	// Set the sender and recipient
	if err := c.Mail(emailSender); err != nil {
		return fmt.Errorf("could not set sender: %v", err)
	}
	if err := c.Rcpt(endemail); err != nil {
		return fmt.Errorf("could not set endemail: %v", err)
	}

	// Send the email
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("could not send data: %v", err)
	}
	if _, err := w.Write([]byte(message)); err != nil {
		return fmt.Errorf("could not write to SMTP: %v", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("could not close SMTP connection: %v", err)
	}

	c.Quit()
	return nil

}

func checkFrozen(conn *pgxpool.Pool, account_num string) error {
	var frozen string
	err := conn.QueryRow(
		context.Background(),
		`SELECT account_status FROM accounts WHERE account_num = $1`,
		account_num,
	).Scan(&frozen)
	if err != nil{
		return err
	}
	if frozen.String == "FROZEN"{
		return fmt.Sprintf("account %s frozen", accnum)
	}
	return nil
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

// Information relating to the current logged in user's session
type LogInSessionCookie struct {
	LoggedIn     bool
	Email        string
	ProfileType  string
	PhoneNumber  string
	PhoneCarrier string
}

// All information relating to the current login attempt
type LogInAttemptCookie struct {
	Email        string
	ProfileType  string
	PhoneNumber  string
	PhoneCarrier string
}

// SetLoggedIn is a helper function to set the login cookies
func SetLoggedIn(w http.ResponseWriter, r *http.Request, attemptCookie *LogInAttemptCookie) {
	session, err := store.Get(r, "current-session")
	handle(err)
	session.Options.MaxAge = 24 * 60 * 60 // 24 hours before automatically logging out
	session.Values["logged-in"] = &LogInSessionCookie{
		LoggedIn:     true,
		Email:        attemptCookie.Email,
		ProfileType:  attemptCookie.ProfileType,
		PhoneNumber:  attemptCookie.PhoneNumber,
		PhoneCarrier: attemptCookie.PhoneCarrier,
	}
	err = session.Save(r, w)
	handle(err)
}

// Returns the type of profile logged in along with a boolean indicating if the user is logged in or not
func checkLoggedIn(r *http.Request, w http.ResponseWriter) (string, bool) {
	session, err := store.Get(r, "current-session")
	handle(err)
	val, ok := session.Values["logged-in"]
	loggedIn := false
	if ok {
		loggedIn = val.(*LogInSessionCookie).LoggedIn
	}
	if loggedIn {
		return val.(*LogInSessionCookie).ProfileType, loggedIn
	}
	return "", loggedIn
}

type transaction struct {
	Name   string    `json:"Name"`
	Type   string    `json:"Type"`
	Amount float64   `json:"Amount"`
	Date   time.Time `json:"Date"`
}

func (t *transaction) MarshalJSON() ([]byte, error) {
	type Alias transaction // Create an alias to avoid recursion
	return json.Marshal(&struct {
		Date string `json:"Date"` // Format the Date field as a string
		*Alias
	}{
		Date:  t.Date.Format(time.RFC3339), // ISO 8601 format
		Alias: (*Alias)(t),
	})
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
