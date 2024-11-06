package main

import (
	"context"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"os"

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

	// Serve static content
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Routes
	http.HandleFunc("/", index)
	http.HandleFunc("/twofa", twofa)
	http.HandleFunc("/login-user", loginUser)
	http.HandleFunc("/login-employee", loginEmployee)
	http.HandleFunc("/forgot-password", forgotPassword)
	http.HandleFunc("/forgot-password-sent", forgotPasswordSent)
	http.HandleFunc("/callback", callback)
	http.HandleFunc("/employee-dashboard", employeeDashboard)
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
		if val.(*LogInSessionCookie).ProfileType == "employee" {
			http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
		} else {
			// TODO: redirect to accounts page instead (once it gets created)
			http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
		}
		return
	}

	RenderTemplate(w, "loginemployee.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
}

func forgotPassword(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "forgotpassword.html")
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
		RenderTemplate(w, "employeehomescreen.html", pongo2.Context{"fname": "Alex"})
	} else {
		// TODO: redirect to user accounts page instead
		// http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		RenderTemplate(w, "employeehomescreen.html", pongo2.Context{"fname": "Alex"})
	}
}
