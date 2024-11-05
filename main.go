package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"time"

	"github.com/MonopolyTechnic/simple-banking-system/models"
	"github.com/gorilla/sessions"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	host        string
	port        string
	env         map[string]string = readEnv("dbinfo.env")
	store                         = sessions.NewCookieStore([]byte("your-secret-key")) // Change this to a secure key
	smsGateways                   = map[string]string{
		"AT&T":               "txt.att.net",
		"T-Mobile":           "tmomail.net",
		"Verizon":            "vtext.com",
		"Sprint":             "sprintpcs.com",
		"Cricket":            "mms.cricketwireless.net",
		"Boost Mobile":       "myboostmobile.com",
		"MetroPCS":           "mymetropcs.com",
		"US Cellular":        "email.uscc.net",
		"Page Plus Cellular": "vtext.com", // Uses Verizon's gateway
		"TracFone":           "mmst5.tracfone.com",
		"Rogers":             "txt.bell.ca",
		"Bell":               "txt.bell.ca",
		"Telus":              "msg.telus.com",
		"Vodafone":           "vodafone.net",
		"O2":                 "o2.co.uk",
		"Orange":             "orange.net",
		"Telenor":            "telenor.no",
		"Telia":              "telia.se",
	}
)

const (
	smtpServer    = "smtp.gmail.com"
	smtpPort      = "587"
	emailSender   = "monopolytechnic@gmail.com"
	emailPassword = "vqdh iwfp cnwf iioh" // App password
	imagePath     = "static/images/piggybank.jpg"
)

func main() {
	// Show file and line number in logs
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Environment variables
	host = env["HOST"]
	port = env["PORT"]

	// Set up tables if they do not exist yet
	exec, err := os.ReadFile("create_tables.sql")
	handle(err)
	err = OpenDBConnection(func(conn *pgxpool.Pool) error {
		_, err := conn.Exec(context.Background(), string(exec))
		handle(err, "Exec failed")

		log.Println("Tables successfully created.")
		return nil
	})
	handle(err)

	// Serve static content
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Routes
	http.HandleFunc("/", index)
	http.HandleFunc("/twofa", twofa)
	http.HandleFunc("/login-user", loginUser)
	http.HandleFunc("/forgot-password", forgotPassword)
	http.HandleFunc("/forgot-password-sent", forgotPasswordSent)
	http.HandleFunc("/callback", callback)
	http.HandleFunc("/verify-code", verifyCode)
	http.HandleFunc("/employee-dashboard", employeeDashboard)

	log.Printf("Running on http://%s:%s (Press CTRL+C to quit)", host, port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	// For some reason Go's net/http interprets / as a wild card path
	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		// TODO: Serve a custom 404 page here instead
		fmt.Fprint(w, "<h1>Page not found.</h1>")
		return
	}

	// A sample read from db
	err := OpenDBConnection(func(conn *pgxpool.Pool) error {
		rows, _ := conn.Query(context.Background(), "SELECT * FROM accounts WHERE primary_customer_id = 3")
		res, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[models.Account])
		handle(err, "CollectRows failed")

		// Print out each row and its values
		var f float64
		for _, r := range res {
			fmt.Println(r.AccountNumber.String)
			fmt.Println(r.PrimaryCustomerID.Int)
			fmt.Println(r.SecondaryCustomerID.Int)
			r.Balance.AssignTo(&f)
			fmt.Println(f)
		}
		fmt.Println(len(res))
		return nil
	})
	handle(err)

	http.ServeFile(w, r, "./templates/index.html")
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	// TODO: serve a login page
	http.ServeFile(w, r, "./templates/loginuser.html")
}

func forgotPassword(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./templates/forgotpassword.html")
}

func callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: authenticate user login here

	http.Redirect(w, r, "/twofa", http.StatusSeeOther)
}

func verifyCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: authenticate code here

	// TODO: redirect to employee or user based on the user (or have separate endpoints)
	http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
}

func forgotPasswordSent(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./templates/postresetpassword.html")
}

func employeeDashboard(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./templates/employeehomescreen.html")
}

func SendCode(phoneNumber, phoneCarrier string) (int, error) {
	carrierGateway, exists := smsGateways[phoneCarrier]
	if !exists {
		return 0, fmt.Errorf("unsupported carrier: %s", phoneCarrier)
	}

	recipientSMS := fmt.Sprintf("%s@%s", phoneNumber, carrierGateway)

	// Generate a random 6-digit verification code
	rand.Seed(time.Now().UnixNano())
	verificationCode := rand.Intn(900000) + 100000

	// Create a multipart message
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	// Write the message part
	message := fmt.Sprintf("Subject: Verification Code\n\nYour verification code is: %d", verificationCode)
	textPart, err := writer.CreateFormField("text")
	if err != nil {
		return 0, fmt.Errorf("could not create text part: %v", err)
	}
	if _, err := textPart.Write([]byte(message)); err != nil {
		return 0, fmt.Errorf("could not write message: %v", err)
	}
	// Add the image part
	imageFile, err := os.Open(imagePath)
	if err != nil {
		return 0, fmt.Errorf("could not open image file: %v", err)
	}
	defer imageFile.Close()

	imagePart, err := writer.CreateFormFile("image", "piggybank.jpg")
	if err != nil {
		return 0, fmt.Errorf("could not create image part: %v", err)
	}
	if _, err := io.Copy(imagePart, imageFile); err != nil {
		return 0, fmt.Errorf("could not write image to part: %v", err)
	}
	// Close the writer to finalize the multipart message
	if err := writer.Close(); err != nil {
		return 0, fmt.Errorf("could not close writer: %v", err)
	}

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
	if _, err := w.Write(buffer.Bytes()); err != nil {
		return 0, fmt.Errorf("could not write to SMTP: %v", err)
	}
	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("could not close SMTP connection: %v", err)
	}

	c.Quit()

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

func twofa(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		phone_number := r.URL.Query().Get("phone_number") // Assuming phone number is passed as a query parameter
		phone_carrier := r.URL.Query().Get("phone_carrier")
		actualCode, err := SendCode(phone_number, phone_carrier)
		session.Values["actualCode"] = actualCode // Store the code in the session
		err = session.Save(r, w)                  // Save the session
		if err != nil {
			http.Error(w, "Unable to save session", http.StatusInternalServerError)
			return
		}

		http.ServeFile(w, r, "./templates/2fa.html")
	} else if r.Method == http.MethodPost {
		code := r.FormValue("code")
		if actualCode, ok := session.Values["actualCode"].(string); ok && code == actualCode {
			// Code is correct, redirect to accounts page
			http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		} else {
			http.Error(w, "Invalid code", http.StatusUnauthorized) //change this for a second attempt?
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
