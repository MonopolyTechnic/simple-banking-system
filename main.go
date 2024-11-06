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

	// Allow encoding of LogInCookie for session cookies
	gob.Register(&LogInCookie{})

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
		fmt.Fprint(w, "<h1>Page not found.</h1>")
		return
	}

	RenderTemplate(w, "index.html")
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	// TODO: redirect to customer dashboard if already logged in
	RenderTemplate(w, "loginuser.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
}

func loginEmployee(w http.ResponseWriter, r *http.Request) {
	// Redirect to employee dashboard if already logged in
	session, err := store.Get(r, "session-name")
	handle(err)
	val, ok := session.Values["logged-in"]
	loggedIn := false
	if ok {
		loggedIn = val.(*LogInCookie).LoggedIn
	}
	if loggedIn {
		http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
	}
	// TODO: change to loginemployee template ?
	RenderTemplate(w, "loginuser.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
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
			"SELECT password_hash, phone_number, phone_carrier FROM profiles WHERE email = $1",
			r.FormValue("email"),
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

	session, err2 := store.Get(r, "session-name")
	handle(err2)

	// Invalid credentials
	if err != nil {
		session.AddFlash("Invalid email or password entered.")
		err2 = session.Save(r, w)
		handle(err2)

		http.Redirect(w, r, "/login-user", http.StatusSeeOther)
		return
	}
	// Valid credentials, move on to 2FA
	redirect_uri := fmt.Sprintf("/twofa?phone_number=%s&phone_carrier=%s", res[0].PhoneNumber.String, res[0].PhoneCarrier.String)
	http.Redirect(w, r, redirect_uri, http.StatusSeeOther)
}

// SetLoggedIn is a helper function to set the login cookies
func SetLoggedIn(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	handle(err)
	val, ok := session.Values["logged-in"]
	var cookie *LogInCookie
	if ok {
		cookie = val.(*LogInCookie)
		cookie.LoggedIn = true
		cookie.Email = "" // TODO: mark which user is logged in and their profile type (employee, customer)
	} else {
		cookie = &LogInCookie{LoggedIn: true, Email: ""}
	}
	session.Values["logged-in"] = cookie
	err = session.Save(r, w)
	handle(err)
}

func employeeDashboard(w http.ResponseWriter, r *http.Request) {
	// Redirect to login if not logged in yet
	session, err := store.Get(r, "session-name")
	handle(err)
	val, ok := session.Values["logged-in"]
	loggedIn := false
	if ok {
		loggedIn = val.(*LogInCookie).LoggedIn
	}
	if !loggedIn {
		http.Redirect(w, r, "/login-employee", http.StatusSeeOther)
	}

	// TODO: Pass in the correct name that is stored in cookies
	RenderTemplate(w, "employeehomescreen.html", pongo2.Context{"fname": "Alex"})
}

func twofa(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		if r.URL.Query().Get("retry") != "true" {
			phone_number := r.URL.Query().Get("phone_number") // Assuming phone number is passed as a query parameter
			phone_carrier := r.URL.Query().Get("phone_carrier")
			actualCode, err := SendCode(phone_number, phone_carrier)
			session.Values["actualCode"] = actualCode // Store the code in the session
			err = session.Save(r, w)                  // Save the session
			if err != nil {
				http.Error(w, "Unable to save session", http.StatusInternalServerError)
				return
			}
		}

		RenderTemplate(w, "2fa.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
	} else if r.Method == http.MethodPost {
		code := r.FormValue("code")
		actualCode, ok := session.Values["actualCode"]
		actualCode = fmt.Sprintf("%d", actualCode)
		if ok && code == actualCode {
			// Code is correct, redirect to accounts page
			SetLoggedIn(w, r)
			// TODO: redirect to employee or user based on the user (or have separate endpoints)
			http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
		} else {
			session.AddFlash("Invalid code.")
			err = session.Save(r, w)
			handle(err)

			http.Redirect(w, r, "/twofa?retry=true", http.StatusSeeOther)
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	// Mark as logged in
	session, err := store.Get(r, "session-name")
	handle(err)
	val, ok := session.Values["logged-in"]
	var cookie *LogInCookie
	if ok {
		cookie = val.(*LogInCookie)
		cookie.LoggedIn = false
		cookie.Email = ""
	} else {
		cookie = &LogInCookie{LoggedIn: false, Email: ""}
	}
	session.Values["logged-in"] = cookie
	err = session.Save(r, w)
	handle(err)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
