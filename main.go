package main

import (
	"context"
	"database/sql"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/MonopolyTechnic/simple-banking-system/models"
	"github.com/flosch/pongo2/v4"
	"github.com/gorilla/sessions"
	"github.com/jackc/pgx/pgtype"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
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
	tokenStore    map[string]time.Time = make(map[string]time.Time)
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
	reset-password-session:
		key token, type time.Time
		Contains the expiration time of the token
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
	http.HandleFunc("/open-account", openAccount)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/list-accounts", listAccounts)
	http.HandleFunc("/user-dashboard", userDashboard)
	http.HandleFunc("/transaction-history", transactionHistory)

	pongo2.RegisterFilter("capitalize", capitalizeFilter)
	pongo2.RegisterFilter("formatBalance", formatBalance)

	log.Printf("Running on http://%s:%s (Press CTRL+C to quit)", host, port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	// For some reason Go's net/http interprets / as a wild card path
	if r.URL.Path != "/" {
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
			http.Redirect(w, r, "/user-dashboard", http.StatusSeeOther)
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
			http.Redirect(w, r, "/user-dashboard", http.StatusSeeOther)
		}
		return
	}

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
	session, err := store.Get(r, "reset-password-session")
	if err != nil {
		fmt.Println("Unable to retrieve session:", err)
		http.Error(w, "Unable to retrieve session", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		token := generateResetToken()
		session.Values[token] = email    // Store the code in the session
		session.Options.MaxAge = 15 * 60 // 15 minutes
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

func resetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Get the token, new password, and confirm password
		token := r.FormValue("token")
		newPassword := r.FormValue("newPassword")
		confirmPassword := r.FormValue("confirmPassword")
		// Check if token is valid
		var email string
		var ok bool
		email, ok = isValidToken(w, r, token)
		if !ok {
			AddFlash(r, w, "Reset link has expired or is invalid.")
			http.Redirect(w, r, "/reset-password?token="+token, http.StatusSeeOther)
			return
		}

		// Check if new password and confirm password match
		if newPassword != confirmPassword {
			// If passwords do not match, show an error message
			AddFlash(r, w, "Passwords do not match.")
			http.Redirect(w, r, "/reset-password?token="+token, http.StatusSeeOther)
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
	RenderTemplate(w, "resetpassword.html", pongo2.Context{"Token": token, "flashes": RetrieveFlashes(r, w)})
}

func forgotPasswordSent(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "postresetpassword.html")
}

func userDashboard(w http.ResponseWriter, r *http.Request) {
	attemptSession, err := store.Get(r, "login-attempt-session")
	handle(err)
	val, ok := attemptSession.Values["data"]
	if !ok {
		http.Redirect(w, r, "/logout", http.StatusSeeOther)
		return
	}
	// Valid sign-in session
	cookie := val.(*LogInAttemptCookie)
	email := cookie.Email
	var accounts []struct {
		AccountNum  string
		AccountType string
		Balance     float64
	}
	var name string
	err = OpenDBConnection(func(conn *pgxpool.Pool) error {
		// Query to get the customer ID for the primary customer email
		var id int
		err := conn.QueryRow(
			context.Background(),
			`SELECT first_name, id FROM profiles WHERE email = $1`,
			email,
		).Scan(&name, &id)

		if err != nil {
			return fmt.Errorf("Invalid email: %s", email)
		}
		rows, err := conn.Query(
			context.Background(),
			`SELECT account_num, account_type, balance FROM accounts WHERE primary_customer_id = $1 OR secondary_customer_id = $1`,
			id, // Use the customer ID obtained earlier
		)

		if err != nil {
			return fmt.Errorf("Invalid return from accounts: %s", email)
		}
		defer rows.Close()

		for rows.Next() {
			var account struct {
				AccountNum  string
				AccountType string
				Balance     float64
			}
			if err := rows.Scan(&account.AccountNum, &account.AccountType, &account.Balance); err != nil {
				return fmt.Errorf("Error scanning account row: %v", err)
			}
			account.Balance = math.Round(account.Balance*100) / 100
			// Append each account to the slice
			accounts = append(accounts, account)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("Error while iterating over account rows: %v", err)
		}
		return nil
	})
	if err != nil {
		AddFlash(r, w, err.Error())
		http.Redirect(w, r, "/user-dashboard", http.StatusSeeOther)
		return
	}
	log.Printf("accounts: %+v", accounts)
	RenderTemplate(w, "accounts_dashboard.html", pongo2.Context{"acclist": accounts, "flashes": RetrieveFlashes(r, w), "fname": name})
}

func transactionHistory(w http.ResponseWriter, r *http.Request) {
	attemptSession, err := store.Get(r, "login-attempt-session")
	handle(err)
	val, ok := attemptSession.Values["data"]
	if !ok {
		http.Redirect(w, r, "/logout", http.StatusSeeOther)
		return
	}
	// Valid sign-in session
	cookie := val.(*LogInAttemptCookie)
	email := cookie.Email
	var accounts []struct {
		Number   string        `json:"Number"`
		Outgoing []transaction `json:"Outgoing"`
		Incoming []transaction `json:"Incoming"`
	}
	var name string
	err = OpenDBConnection(func(conn *pgxpool.Pool) error {
		// Query to get the customer ID for the primary customer email
		var id int
		err := conn.QueryRow(
			context.Background(),
			`SELECT first_name, id FROM profiles WHERE email = $1`,
			email,
		).Scan(&name, &id)
		if err != nil {
			return fmt.Errorf("Invalid email: %s", email)
		}
		accrows, err := conn.Query(
			context.Background(),
			`SELECT account_num FROM accounts WHERE primary_customer_id = $1 OR secondary_customer_id = $1`,
			id, // Use the customer ID obtained earlier
		)

		if err != nil {
			return fmt.Errorf("Invalid return from accounts: %s", email)
		}
		defer accrows.Close()
		for accrows.Next() {
			outgoing := []transaction{}
			incoming := []transaction{}
			var accnum string
			if err := accrows.Scan(&accnum); err != nil {
				return fmt.Errorf("Error getting account: %v", err)
			}
			rows, err := conn.Query(
				context.Background(),
				`SELECT
					source_account,
					recipient_account,
					amount,
					transaction_type,
					transaction_timestamp
				FROM transactions
				WHERE source_account = $1 OR recipient_account = $1
				ORDER BY transaction_timestamp DESC
				`,
				accnum, // Use the customer ID obtained earlier
			)

			if err != nil {
				return fmt.Errorf("Invalid return from accounts: %s", email)
			}
			defer rows.Close()

			for rows.Next() {
				var sc sql.NullString
				var rc string
				var tmp struct {
					AccNum string
					Type   string
					Amount float64
					Date   time.Time
				}
				if err := rows.Scan(&sc, &rc, &tmp.Amount, &tmp.Type, &tmp.Date); err != nil {
					return fmt.Errorf("Error scanning account row: %v", err)
				}
				if sc.String == accnum {
					tmp.AccNum = rc
				} else {
					tmp.AccNum = sc.String
				}
				var othername string
				if tmp.AccNum == "" {
					if tmp.Type == "deposit" {
						othername = "ATM DEPOSIT"
					} else {
						othername = "ATM WITHDRAWAL"
					}
				} else {
					var pcid int
					var scidnull sql.NullInt32
					err := conn.QueryRow(
						context.Background(),
						`SELECT primary_customer_id, secondary_customer_id FROM accounts WHERE account_num = $1`,
						tmp.AccNum, // Use the customer ID obtained earlier
					).Scan(&pcid, &scidnull)
					if err != nil {
						return fmt.Errorf("Account Number cannot be displayed. %v", err)
					}
					var fn string
					var mn sql.NullString
					var ln string
					err = conn.QueryRow(
						context.Background(),
						`SELECT first_name, middle_name, last_name FROM profiles WHERE id = $1`,
						pcid, // Use the customer ID obtained earlier
					).Scan(&fn, &mn, &ln)
					if err != nil {
						return fmt.Errorf("Name of account %s cannot be displayed 2. %v", pcid, err)
					}
					if !mn.Valid {
						othername = fn + " " + ln
					} else {
						othername = fn + " " + mn.String + " " + ln
					}
					if scidnull.Valid {
						scid := scidnull.Int32
						othername = othername + ", "
						err := conn.QueryRow(
							context.Background(),
							`SELECT first_name, middle_name, last_name FROM profiles WHERE id = $1`,
							scid, // Use the customer ID obtained earlier
						).Scan(&fn, &mn, &ln)
						if err != nil {
							return fmt.Errorf("Name of account %s cannot be displayed.", pcid)
						}
						if !mn.Valid {
							othername += fn + " " + ln
						} else {
							othername += fn + " " + mn.String + " " + ln
						}
					}
				}
				var tran = transaction{
					Name:   othername,
					Type:   tmp.Type,
					Amount: tmp.Amount,
					Date:   tmp.Date,
				}
				if sc.String == accnum {
					outgoing = append(outgoing, tran)
				} else {
					incoming = append(incoming, tran)
				}
			}
			var acc struct {
				Number   string        `json:"Number"`
				Outgoing []transaction `json:"Outgoing"`
				Incoming []transaction `json:"Incoming"`
			}
			acc.Number = accnum
			acc.Outgoing = outgoing
			acc.Incoming = incoming
			accounts = append(accounts, acc)
		}
		if err := accrows.Err(); err != nil {
			return fmt.Errorf("Error while iterating over account rows: %v", err)
		}
		return nil
	})
	if err != nil {
		AddFlash(r, w, err.Error())
		http.Redirect(w, r, "/user-dashboard", http.StatusSeeOther)
		return
	}
	//log.Printf("accounts: %+v", accounts)
	acclistJSON, err := json.Marshal(accounts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	acclistJSONString := string(acclistJSON)
	//log.Printf("accountsJSONString: %s", acclistJSONString)
	RenderTemplate(w, "transaction_history.html", pongo2.Context{"acclistJSON": acclistJSONString, "acclist": accounts, "flashes": RetrieveFlashes(r, w), "fname": name})
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

	// Invalid credentials
	if err != nil {
		AddFlash(r, w, "Invalid email or password entered.")

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
				http.Redirect(w, r, "/user-dashboard", http.StatusSeeOther)
			}
		} else {
			if ok {
				AddFlash(r, w, "Invalid code.")
				http.Redirect(w, r, "/twofa?retry=true", http.StatusSeeOther)
			} else {
				// code not found: code expired
				AddFlash(r, w, "Code has expired. We will send another code to your phone.")
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
		http.Redirect(w, r, "/user-dashboard", http.StatusSeeOther)
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
		phoneNum = stripNonAlphanumeric(phoneNum)
		carrier := r.FormValue("carrier")
		if _, exists := smsGateways[carrier]; !exists {
			AddFlash(r, w, "Carrier not in list of provided carriers.")

			http.Redirect(w, r, "/add-user", http.StatusSeeOther)
			return
		}
		password := r.FormValue("pw")
		// Date of Birth
		dob := r.FormValue("dob")
		// Billing Address
		billingAddress := strings.ReplaceAll(r.FormValue("billing_address"), "\r", "")

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
					$1,
					$2, 
					$3, 
					$4, 
					$5, 
					$6, 
					$7, 
					$8
				);`,
				firstName,
				lastName,
				email,
				dob,            // Include Date of Birth
				billingAddress, // Include Billing Address
				phoneNum,
				carrier,
				passwordHash,
			)

			// Check for error and return if any
			if err != nil {
				return fmt.Errorf("Failed to insert user into database: %v", err)
			}

			// Success, return nil to indicate the user has been added
			return nil
		})
		if err != nil {
			AddFlash(r, w, err.Error())
			http.Redirect(w, r, "/add-user", http.StatusSeeOther)
			return
		}

		// Flash message after successful insertion
		AddFlash(r, w, "User added successfully!")

		// Respond with a success message
		http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
	}

	// Quality of life improvement would be to somehow persist the form data for a retry
	// Render the add user form (in case of GET request or on error)
	RenderTemplate(w, "adduser.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
}

func openAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {

		// Parse form data
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		// Extract primary customer ID
		primaryCustomerEmail := r.FormValue("primary_customer_email")
		var secondaryCustomerEmail string
		if r.FormValue("secondary_customer_email") != "" {
			secondaryCustomerEmail = r.FormValue("secondary_customer_email")
			if primaryCustomerEmail == secondaryCustomerEmail {
				AddFlash(r, w, "Primary and secondary email cannot be identical.")
				http.Redirect(w, r, "/open-account", http.StatusSeeOther)
				return
			}
		}

		var primaryCustomerID int
		var secondaryCustomerID int
		rc := 0
		err = OpenDBConnection(func(conn *pgxpool.Pool) error {
			// Query to get the customer ID for the primary customer email
			err := conn.QueryRow(
				context.Background(),
				`SELECT id FROM profiles WHERE email = $1`,
				primaryCustomerEmail,
			).Scan(&primaryCustomerID)

			if err != nil {
				return fmt.Errorf("Invalid primary email: %s", primaryCustomerEmail)
			}

			// If a secondary email is provided, get the customer ID for the secondary customer
			if secondaryCustomerEmail != "" {
				err := conn.QueryRow(
					context.Background(),
					`SELECT id FROM profiles WHERE email = $1`,
					secondaryCustomerEmail,
				).Scan(&secondaryCustomerID)

				if err != nil {
					return fmt.Errorf("Invalid secondary email: %s", secondaryCustomerEmail)
				}
			}
			err = conn.QueryRow(
				context.Background(),
				`SELECT COUNT(*) FROM accounts`,
			).Scan(&rc)

			// Check for errors
			if err != nil {
				return fmt.Errorf("failed to get row count from profiles: %v", err)
			}
			// At this point, both primaryCustomerID and secondaryCustomerID should be populated
			return nil
		})

		if err != nil {
			AddFlash(r, w, err.Error())
			http.Redirect(w, r, "/open-account", http.StatusSeeOther)
			return
		}
		rc = rc + 1
		accountNum := fmt.Sprintf("%016d", rc)
		// Extract account type
		accountType := r.FormValue("account_type")
		if accountType != "checking" && accountType != "savings" {
			AddFlash(r, w, "Invalid account type.")
			http.Redirect(w, r, "/open-account", http.StatusSeeOther)
			return
		}

		// Extract initial balance
		balance, err := strconv.ParseFloat(r.FormValue("balance"), 64)
		if err != nil || balance < 0 {
			AddFlash(r, w, "Invalid initial deposit amount.")
			http.Redirect(w, r, "/open-account", http.StatusSeeOther)
			return
		}

		// Insert the new account into the 'accounts' table
		err = OpenDBConnection(func(conn *pgxpool.Pool) error {
			// Prepare SQL insert statement
			query := `
				INSERT INTO accounts (
					account_num,
					primary_customer_id,
					secondary_customer_id,
					account_type,
					balance
				) VALUES (
					$1, $2, $3, $4, $5
				)`

			// Execute the query
			_, err := conn.Exec(
				context.Background(),
				query,
				accountNum,          // Account number
				primaryCustomerID,   // Primary customer ID
				secondaryCustomerID, // Secondary customer ID (can be NULL)
				accountType,         // Account type (checking/savings)
				balance,             // Initial balance
			)

			// Check for errors during the insert
			if err != nil {
				return fmt.Errorf("Failed to insert user into database: %v", err)
			}

			// Success, return nil to indicate the insert was successful
			return nil
		})

		if err != nil {
			AddFlash(r, w, err.Error())
			http.Redirect(w, r, "/open-account", http.StatusSeeOther)
			return
		}
		// Flash message after successful insertion
		AddFlash(r, w, "Account added successfully!")

		// Respond with a success message
		http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
		return
	}
	RenderTemplate(w, "openaccount.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
}

func listAccounts(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "current-session")
	handle(err)
	val, ok := session.Values["logged-in"]
	loggedIn := false
	if ok {
		loggedIn = val.(*LogInSessionCookie).LoggedIn
	}
	if !loggedIn {
		http.Error(w, "Unauthorized request", http.StatusUnauthorized)
		return
	}

	if val.(*LogInSessionCookie).ProfileType != "employee" {
		http.Error(w, "Unauthorized request", http.StatusUnauthorized)
		return
	}

	customerEmail := r.URL.Query().Get("email")
	var customerID int
	var accountData []models.Account
	err = OpenDBConnection(func(conn *pgxpool.Pool) error {
		err := conn.QueryRow(
			context.Background(),
			`SELECT id FROM profiles WHERE email = $1 AND profile_type = 'customer'`,
			customerEmail,
		).Scan(&customerID)

		if err != nil {
			return fmt.Errorf("could not find customer matching given email: %v", err)
		}

		rows, _ := conn.Query(
			context.Background(),
			"SELECT account_num, primary_customer_id, secondary_customer_id, account_type, balance FROM accounts WHERE primary_customer_id = $1 OR secondary_customer_id = $1",
			customerID,
		)
		res, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[models.Account])
		handle(err, "CollectRows failed")
		if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
		accountData = res

		return nil
	})

	if err != nil {
		handle(err, "Query failed")
	}

	type JSONAccount struct {
		AccountNumber       string  `json:"accountNum"`
		PrimaryCustomerID   int32   `json:"primaryCustomerId"`
		SecondaryCustomerID int32   `json:"secondaryCustomerId"`
		AccountType         string  `json:"accountType"`
		Balance             float64 `json:"balance"`
	}

	jsonData := make([]JSONAccount, len(accountData))
	for i, item := range accountData {
		if item.AccountNumber.Status == pgtype.Present {
			jsonData[i].AccountNumber = item.AccountNumber.String
		}
		if item.PrimaryCustomerID.Status == pgtype.Present {
			jsonData[i].PrimaryCustomerID = item.PrimaryCustomerID.Int
		}
		if item.SecondaryCustomerID.Status == pgtype.Present {
			jsonData[i].SecondaryCustomerID = item.SecondaryCustomerID.Int
		}
		if item.AccountType.Status == pgtype.Present {
			jsonData[i].AccountType = item.AccountType.String
		}
		if item.Balance.Status == pgtype.Present {
			jsonData[i].Balance = float64(item.Balance.Int.Int64()) * math.Pow(10, float64(item.Balance.Exp))
		}
	}

	jsonBytes, err := json.Marshal(jsonData)
	if err != nil {
		handle(err, "Failed to generate JSON")
	}

	w.Header().Add("Content-Type", "application/json")
	w.Write(jsonBytes)
}
