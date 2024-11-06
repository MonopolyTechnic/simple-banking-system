package main

import (
	"context"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"math/rand"

	"github.com/MonopolyTechnic/simple-banking-system/models"
	"github.com/flosch/pongo2/v4"
	"github.com/gorilla/sessions"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
	"errors"
)

var (
	host        string
	port        string
	env         map[string]string     = readEnv(".env")
	store       *sessions.CookieStore = sessions.NewCookieStore([]byte("your-secret-key")) // Change this to a secure key
	smsGateways map[string]string     = map[string]string{
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
	tokenStore map[string]time.Time = make(map[string]time.Time)
	emailSender   string
	emailPassword string
)

const (
	smtpServer = "smtp.gmail.com"
	smtpPort   = "587"
	imagePath  = "static/images/piggybank.jpg"
)

/* 	Session name info:
   	current-session:
		key "logged-in" type LogInSessionCookie
		Contains info for the current logged in user's session
		Expires after 24 hours
	current-attempt-session:
		key "data", type LogInAttemptCookie
		Contains info about the current log in attempt
		Expires after 30 minutes
	twofa-session:
		key "actualCode", type int
		Contains the verification code for the current login attempt
		Expires after 10 minutes
	flash-session:
		Contains any flash messages to show
		Added using session.AddFlash()
*/

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
		handle(err, "Table creation failed")

		log.Println("Tables successfully created.")
		return nil
	})
	handle(err)

	// Allow encoding of LogInSessionCookie for session cookies
	gob.Register(&LogInSessionCookie{})
	gob.Register(&LogInAttemptCookie{})
	gob.Register(time.Time{})

	// Serve static content
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Routes
	http.HandleFunc("/", index)
	http.HandleFunc("/twofa", twofa)
	http.HandleFunc("/login-user", loginUser)
	http.HandleFunc("/login-employee", loginEmployee)
	http.HandleFunc("/forgot-password", forgotPassword)
	http.HandleFunc("/reset-password", resetPassword)
	http.HandleFunc("/postresetpassword", forgotPasswordSent)
	http.HandleFunc("/callback", callback)
	http.HandleFunc("/employee-dashboard", employeeDashboard)
	http.HandleFunc("/add-user", addUser)
	http.HandleFunc("/logout", logout)

	log.Printf("Running on http://%s:%s (Press CTRL+C to quit)", host, port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	// For some reason Go's net/http interprets / as a wild card path
	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		// TODO: Serve a custom 404 page here instead
		http.Error(w, "Page not found.", http.StatusNotFound)
		return
	}

	RenderTemplate(w, "index.html")
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	// Check if already logged in
	session, err := store.Get(r, "current-session")
	handle(err)
	val, ok := session.Values["logged-in"]
	loggedIn := false
	if ok {
		loggedIn = val.(*LogInSessionCookie).LoggedIn
	}
	if loggedIn {
		if val.(*LogInSessionCookie).ProfileType == "employee" {
			http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
		} else {
			// TODO: redirect to accounts page instead (once it gets created)
			http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
		}
		return
	}

	RenderTemplate(w, "loginuser.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
}

func loginEmployee(w http.ResponseWriter, r *http.Request) {
	// Check if already logged in
	session, err := store.Get(r, "current-session")
	handle(err)
	val, ok := session.Values["logged-in"]
	loggedIn := false
	if ok {
		loggedIn = val.(*LogInSessionCookie).LoggedIn
	}
	if loggedIn {
		http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
	}
	// TODO: change to loginemployee template ?
	RenderTemplate(w, "loginemployee.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
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


func forgotPassword(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		fmt.Println("Unable to retrieve session:", err)
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodPost {
		expirationTime := time.Now().Add(15*time.Minute)
		email := r.FormValue("email")
		token := generateResetToken()
		session.Values[token] = expirationTime // Store the code in the session
		err = session.Save(r, w)
		if err != nil {
			fmt.Printf("Failed to save session: %v", err) // Log the actual error
			http.Error(w, "Unable to save session", http.StatusInternalServerError)
			return
		}
		body := fmt.Sprintf("Click the link below to reset your password.\n\nhttp://%s:%s/reset-password?token=%s", host, port, token)
		err := SendEmail(email, "Forgot Password", body)
		if err != nil {
			log.Printf("Failed to send email: %v", err)
			http.Error(w, "Failed to send email", http.StatusInternalServerError)
			return
		}

		// Inform the user that an email has been sent
		// For example, you can redirect the user or render a confirmation page
		http.Redirect(w, r, "/postresetpassword", http.StatusSeeOther)
	}
	RenderTemplate(w, "forgotpassword.html")
}

func isValidToken(w http.ResponseWriter, r *http.Request, token string) bool {
	// Check if the token exists
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return false
	}
	expirationTime, exists := session.Values[token].(time.Time)
	if !exists {
		return false // Token not found
	}

	// Check if the token has expired
	if time.Now().After(expirationTime) {
		delete(tokenStore, token) // Remove expired token from the store
		return false
	}

	return true
}

func resetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Get the token, new password, and confirm password
		token := r.FormValue("token")
		email := r.FormValue("email")
		newPassword := r.FormValue("newPassword")
		confirmPassword := r.FormValue("confirmPassword")
		// Check if token is valid
		if !isValidToken(w, r, token) {
			http.Error(w, "Reset link has expired or is invalid", http.StatusBadRequest)
			return
		}

		// Check if new password and confirm password match
		if newPassword != confirmPassword {
			// If passwords do not match, show an error message
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			return
		}

		// Proceed with updating the password (e.g., update the database)
		// UpdatePassword(token, newPassword)
		err := OpenDBConnection(func(conn *pgxpool.Pool) error {
	
			// Hash the new password before saving it
			newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
	
			// Update the password hash in the database
			_, err = conn.Exec(
				context.Background(),
				"UPDATE profiles SET password_hash = $1 WHERE email = $2",
				newPasswordHash,
				email,
			)
			if err != nil {
				return err
			}
	
			// Success, return nil to indicate the password has been updated
			return nil
		})
	
		// Handle errors or success
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Success message (you can also redirect to a success page)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Render reset password form (pass token as part of context)
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	// Render the form with the token
	RenderTemplate(w, "resetpassword.html", map[string]interface{}{"Token": token})
}

func forgotPasswordSent(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "postresetpassword.html")
}

// Callback endpoint for login requests
func callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var res []models.Profile
	var err2 error

	// Check the database for this profile
	err := OpenDBConnection(func(conn *pgxpool.Pool) error {
		rows, _ := conn.Query(
			context.Background(),
			"SELECT profile_type, password_hash, phone_number, phone_carrier FROM profiles WHERE email = $1 AND profile_type = $2",
			r.FormValue("email"),
			r.URL.Query().Get("profile_type"),
		)
		res, err2 = pgx.CollectRows(rows, pgx.RowToStructByNameLax[models.Profile])
		handle(err2, "CollectRows failed")

		if len(res) == 0 {
			return errors.New("Invalid credentials")
		}
		// Check the password against its hash
		err := bcrypt.CompareHashAndPassword(res[0].PasswordHash.Bytes, []byte(r.FormValue("password")))
		if err != nil {
			return errors.New("Invalid credentials")
		}
		return nil
	})

	flashSession, err2 := store.Get(r, "flash-session")
	handle(err2)

	// Invalid credentials
	if err != nil {
		flashSession.AddFlash("Invalid email or password entered.")
		err2 = flashSession.Save(r, w)
		handle(err2)

		if r.URL.Query().Get("profile_type") == "employee" {
			http.Redirect(w, r, "/login-employee", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/login-user", http.StatusSeeOther)
		}
		return
	}
	// Valid credentials, move on to 2FA
	attemptSession, err := store.Get(r, "login-attempt-session")
	handle(err)
	attemptSession.Values["data"] = &LogInAttemptCookie{
		Email:        r.FormValue("email"),
		ProfileType:  res[0].ProfileType.String,
		PhoneNumber:  res[0].PhoneNumber.String,
		PhoneCarrier: res[0].PhoneCarrier.String,
	}
	attemptSession.Options.MaxAge = 30 * 60 // 30 minutes
	err = attemptSession.Save(r, w)
	handle(err)

	redirect_uri := fmt.Sprintf("/twofa")
	http.Redirect(w, r, redirect_uri, http.StatusSeeOther)
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

func twofa(w http.ResponseWriter, r *http.Request) {
	// Get the session
	twofaSession, err := store.Get(r, "twofa-session")
	handle(err)
	twofaSession.Options.MaxAge = 10 * 60 // 10 minutes

	if r.Method == http.MethodGet {
		if r.URL.Query().Get("retry") != "true" {
			attemptSession, err := store.Get(r, "login-attempt-session")
			handle(err)
			val, ok := attemptSession.Values["data"]
			if !ok {
				http.Error(w, "Your sign-in session has timed out. Please sign in again.", http.StatusUnauthorized)
				return
			}
			// Valid sign-in session
			cookie := val.(*LogInAttemptCookie)
			phone_number := cookie.PhoneNumber
			phone_carrier := cookie.PhoneCarrier
			actualCode, err := SendCode(phone_number, phone_carrier)
			if err != nil {
				http.Error(w, "Unable to send code", http.StatusInternalServerError)
				handle(err)
				return
			}
			twofaSession.Values["actualCode"] = actualCode // Store the code in the session
			// log.Println(actualCode)
			err = twofaSession.Save(r, w) // Save the session
			handle(err)
		}

		RenderTemplate(w, "2fa.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
	} else if r.Method == http.MethodPost {
		code := r.FormValue("code")
		actualCode, ok := twofaSession.Values["actualCode"]
		actualCode = fmt.Sprintf("%d", actualCode)
		if ok && code == actualCode {
			// Code is correct, redirect to employee dashboard or accounts page
			attemptSession, err := store.Get(r, "login-attempt-session")
			handle(err)
			val, ok := attemptSession.Values["data"]
			if !ok {
				http.Error(w, "Your sign-in session has timed out. Please sign in again.", http.StatusUnauthorized)
				return
			}
			cookie := val.(*LogInAttemptCookie)
			SetLoggedIn(w, r, cookie)

			if cookie.ProfileType == "employee" {
				http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
			} else {
				// TODO: redirect to accounts page instead (once it gets created)
				http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
			}
		} else {
			flashSession, err := store.Get(r, "flash-session")
			handle(err)
			if ok {
				flashSession.AddFlash("Invalid code.")
				err = flashSession.Save(r, w)
				handle(err)

				http.Redirect(w, r, "/twofa?retry=true", http.StatusSeeOther)
			} else {
				// code not found: code expired
				flashSession.AddFlash("Code has expired. We will send another code to your phone.")
				err = flashSession.Save(r, w)
				handle(err)

				http.Redirect(w, r, "/twofa", http.StatusSeeOther)
			}

		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	// Mark as logged in
	session, err := store.Get(r, "current-session")
	handle(err)

	session.Values["logged-in"] = &LogInSessionCookie{
		LoggedIn:     false,
		Email:        "",
		ProfileType:  "",
		PhoneNumber:  "",
		PhoneCarrier: "",
	}
	err = session.Save(r, w)
	handle(err)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func employeeDashboard(w http.ResponseWriter, r *http.Request) {
	// Redirect to login if not logged in yet
	session, err := store.Get(r, "current-session")
	handle(err)
	val, ok := session.Values["logged-in"]
	loggedIn := false
	if ok {
		loggedIn = val.(*LogInSessionCookie).LoggedIn
	}
	if !loggedIn {
		http.Redirect(w, r, "/login-employee", http.StatusSeeOther)
		return
	}

	if val.(*LogInSessionCookie).ProfileType == "employee" {
		// TODO: Pass in the correct name that is stored in cookies
		RenderTemplate(w, "employeehomescreen.html", pongo2.Context{"fname": "Alex", "flashes": RetrieveFlashes(r, w)})
	} else {
		// TODO: redirect to user accounts page instead
		// http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		RenderTemplate(w, "employeehomescreen.html", pongo2.Context{"fname": "Alex", "flashes": RetrieveFlashes(r, w)})
	}
}

func addUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Parse form data
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form data", http.StatusBadRequest)
			return
		}

		// Extract the data from the form
		firstName := r.FormValue("fname")
		lastName := r.FormValue("lname")
		email := r.FormValue("email")
		phoneNum := r.FormValue("phonenum")
		carrier := r.FormValue("carrier")
		password := r.FormValue("pw")
		dob := r.FormValue("dob") // Date of Birth
		billingAddress := r.FormValue("billing_address") // Billing Address

		// Hash the password
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}

		// Insert the new user into the database
		err = OpenDBConnection(func(conn *pgxpool.Pool) error {
			_, err := conn.Exec(
				context.Background(),
				`INSERT INTO profiles (
					profile_type,
					first_name,
					last_name,
					email,
					date_of_birth,
					billing_address,
					phone_number,
					phone_carrier,
					password_hash
				) VALUES (
					'customer', 
					COALESCE(NULLIF($1, ''), 'Admin'), 
					COALESCE(NULLIF($2, ''), 'User'), 
					COALESCE(NULLIF($3, ''), 'admin@company.com'), 
					$4, 
					$5, 
					$6, 
					$7, 
					$8
				);`,
				firstName,
				lastName,
				email,
				dob,                // Include Date of Birth
				billingAddress,     // Include Billing Address
				phoneNum,
				carrier,
				passwordHash,
			)

			// Check for error and return if any
			if err != nil {
				return fmt.Errorf("failed to insert user into database: %v", err)
			}

			// Success, return nil to indicate the user has been added
			return nil
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to add user: %v", err), http.StatusInternalServerError)
			return
		}

		// Flash message after successful insertion
		flashSession, err2 := store.Get(r, "flash-session")
		handle(err2)
		flashSession.AddFlash("User added successfully!")
		err2 = flashSession.Save(r, w)
		handle(err2)

		// Respond with a success message
		http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
	}

	// Render the add user form (in case of GET request or on error)
	RenderTemplate(w, "adduser.html")
}