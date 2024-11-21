package main

import (
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
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
	http.Handle("/scripts/", http.StripPrefix("/scripts/", http.FileServer(http.Dir("./scripts"))))

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
	http.HandleFunc("/make-transaction", makeTransaction)
	http.HandleFunc("/list-potential-emails", listPotentialEmails)
	http.HandleFunc("/forgot-email", forgotEmail)
	http.HandleFunc("/verify-email-to-recover", verifyEmailToRecover)
	http.HandleFunc("/post-recovered-email", postRecoveredEmail)

	pongo2.RegisterFilter("getFlashType", getFlashType)
	pongo2.RegisterFilter("getFlashMessage", getFlashMessage)
	http.HandleFunc("/user-dashboard", userDashboard)

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
	profileType, loggedIn := checkLoggedIn(r, w)
	if loggedIn {
		if profileType == "employee" {
			http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/user-dashboard", http.StatusSeeOther)
		}
		return
	}

	RenderTemplate(w, "loginuser.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
}

func loginEmployee(w http.ResponseWriter, r *http.Request) {
	profileType, loggedIn := checkLoggedIn(r, w)
	if loggedIn {
		if profileType == "employee" {
			http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/user-dashboard", http.StatusSeeOther)
		}
		return
	}

	RenderTemplate(w, "loginemployee.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
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
			AddFlash(r, w, "eReset link has expired or is invalid.")
			http.Redirect(w, r, "/reset-password?token="+token, http.StatusSeeOther)
			return
		}

		// Check if new password and confirm password match
		if newPassword != confirmPassword {
			// If passwords do not match, show an error message
			AddFlash(r, w, "ePasswords do not match.")
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
	profileType, loggedIn := checkLoggedIn(r, w)
	if !loggedIn {
		http.Redirect(w, r, "/login-user", http.StatusSeeOther)
		return
	}
	if profileType == "employee" {
		http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
		return
	}

	// Valid sign-in session
	session, err := store.Get(r, "current-session")
	handle(err)
	val, _ := session.Values["logged-in"]
	email := val.(*LogInSessionCookie).Email
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
		AddFlash(r, w, "e"+err.Error())
		http.Redirect(w, r, "/user-dashboard", http.StatusSeeOther)
		return
	}
	RenderTemplate(w, "accounts_dashboard.html", pongo2.Context{"acclist": accounts, "flashes": RetrieveFlashes(r, w), "fname": name})
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
		AddFlash(r, w, "eInvalid email or password entered.")

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
				AddFlash(r, w, "eInvalid code.")
				http.Redirect(w, r, "/twofa?retry=true", http.StatusSeeOther)
			} else {
				// code not found: code expired
				AddFlash(r, w, "eCode has expired. We will send another code to your phone.")
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
	profileType, loggedIn := checkLoggedIn(r, w)
	if !loggedIn {
		http.Redirect(w, r, "/login-employee", http.StatusSeeOther)
		return
	}
	if profileType == "employee" {
		// TODO: Pass in the correct name that is stored in cookies
		RenderTemplate(w, "employeehomescreen.html", pongo2.Context{"fname": "Alex", "flashes": RetrieveFlashes(r, w)})
	} else {
		http.Redirect(w, r, "/user-dashboard", http.StatusSeeOther)
	}
}

func addUser(w http.ResponseWriter, r *http.Request) {
	profileType, loggedIn := checkLoggedIn(r, w)
	if !loggedIn {
		http.Redirect(w, r, "/login-employee", http.StatusSeeOther)
		return
	}
	if profileType != "employee" {
		http.Error(w, "Unauthorized Request", http.StatusUnauthorized)
		return
	}

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
			AddFlash(r, w, "eCarrier not in list of provided carriers.")

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
			AddFlash(r, w, "e"+err.Error())
			http.Redirect(w, r, "/add-user", http.StatusSeeOther)
			return
		}

		// Flash message after successful insertion
		AddFlash(r, w, "sUser added successfully!")

		// Respond with a success message
		http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
	}

	// Quality of life improvement would be to somehow persist the form data for a retry
	// Render the add user form (in case of GET request or on error)
	RenderTemplate(w, "adduser.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
}

func openAccount(w http.ResponseWriter, r *http.Request) {
	profileType, loggedIn := checkLoggedIn(r, w)
	if !loggedIn {
		http.Redirect(w, r, "/login-employee", http.StatusSeeOther)
		return
	}
	if profileType != "employee" {
		http.Error(w, "Unauthorized Request", http.StatusUnauthorized)
		return
	}

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
				AddFlash(r, w, "ePrimary and secondary email cannot be identical.")
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
			AddFlash(r, w, "e"+err.Error())
			http.Redirect(w, r, "/open-account", http.StatusSeeOther)
			return
		}
		rc = rc + 1
		accountNum := fmt.Sprintf("%016d", rc)
		// Extract account type
		accountType := r.FormValue("account_type")
		if accountType != "checking" && accountType != "savings" {
			AddFlash(r, w, "eInvalid account type.")
			http.Redirect(w, r, "/open-account", http.StatusSeeOther)
			return
		}

		// Extract initial balance
		balance, err := strconv.ParseFloat(r.FormValue("balance"), 64)
		if err != nil || balance < 0 {
			AddFlash(r, w, "eInvalid initial deposit amount.")
			http.Redirect(w, r, "/open-account", http.StatusSeeOther)
			return
		}
		//if secondaryID is 0 , then it is not joint account and we do an insert
		//query without secondaryID
		if secondaryCustomerID == 0 {
			// Insert the new not joint account into the 'accounts' table
			err = OpenDBConnection(func(conn *pgxpool.Pool) error {
				// Prepare SQL insert statement
				query := `
					INSERT INTO accounts (
						account_num,
						primary_customer_id,
						account_type,
						balance
					) VALUES (
						$1, $2, $3, $4
					)`
				log.Println("secondaryCustomerID is", secondaryCustomerID)
				// Execute the query
				_, err := conn.Exec(
					context.Background(),
					query,
					accountNum,        // Account number
					primaryCustomerID, // Primary customer ID
					accountType,       // Account type (checking/savings)
					balance,           // Initial balance
				)

				// Check for errors during the insert
				if err != nil {
					return fmt.Errorf("Failed to insert user into database: %v", err)
				}

				// Success, return nil to indicate the insert was successful
				return nil
			})
		} else {
			// Insert the new joint account with secondaryID into the 'accounts' table
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
				log.Println("secondaryCustomerID is", secondaryCustomerID)
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
		}
		if err != nil {
			AddFlash(r, w, "e"+err.Error())
			http.Redirect(w, r, "/open-account", http.StatusSeeOther)
			return
		}
		// Flash message after successful insertion
		AddFlash(r, w, "sAccount added successfully!")

		// Respond with a success message
		http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
		return
	}
	RenderTemplate(w, "openaccount.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
}

func listAccounts(w http.ResponseWriter, r *http.Request) {
	profileType, loggedIn := checkLoggedIn(r, w)
	if !loggedIn {
		http.Error(w, "Unauthorized request", http.StatusUnauthorized)
		return
	}

	if profileType != "employee" {
		http.Error(w, "Unauthorized request", http.StatusUnauthorized)
		return
	}

	customerEmail := r.URL.Query().Get("email")
	var customerID int
	var accountData []models.Account
	err := OpenDBConnection(func(conn *pgxpool.Pool) error {
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
		AddFlash(r, w, "eNo matching email.")
		http.Error(w, "No matching email", http.StatusNotFound)
		return
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

func makeTransaction(w http.ResponseWriter, r *http.Request) {
	profileType, loggedIn := checkLoggedIn(r, w)
	if !loggedIn {
		http.Redirect(w, r, "/login-employee", http.StatusSeeOther)
		return
	}
	if profileType != "employee" {
		http.Error(w, "Unauthorized Request", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPost {
		// Parse form data
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form data", http.StatusBadRequest)
			return
		}

		// Extract the data from the form
		transactionType := r.FormValue("transaction_type")
		if transactionType != "deposit" && transactionType != "withdraw" {
			AddFlash(r, w, "eInvalid transaction type.")
			http.Redirect(w, r, "/make-transaction", http.StatusSeeOther)
			return
		}
		source := r.FormValue("source")
		recipient := r.FormValue("recipient")
		if recipient == "" {
			AddFlash(r, w, "eRecipient is a required field.")
			http.Redirect(w, r, "/make-transaction", http.StatusSeeOther)
			return
		}
		// Extract transaction amount
		amount, err := strconv.ParseFloat(r.FormValue("amount"), 64)

		// Create the transaction and update the account balance
		// Postgres only supports positional args ($1, $2, etc.) for 1 query, so must use fmt.Sprintf instead
		err = OpenDBConnection(func(conn *pgxpool.Pool) error {
			_, err := conn.Exec(
				context.Background(),
				fmt.Sprintf(
					`DO
					$do$
					BEGIN
						INSERT INTO transactions(
							source_account, recipient_account, amount, transaction_type, transaction_timestamp
						) VALUES (
							NULLIF('%[1]s', ''), '%[2]s', %[3]f::numeric, '%[4]s', NOW()
						);

						-- source -> recipient

						UPDATE accounts SET balance=(
							SELECT balance + (
								CASE
									WHEN '%[4]s'='deposit' THEN %[3]f::numeric
									WHEN '%[4]s'='withdraw' THEN -1 * %[3]f::numeric
									ELSE %[3]f::numeric
								END
							)
							FROM accounts WHERE account_num='%[2]s'
						)
						WHERE account_num='%[2]s';

						IF '%[1]s' <> '' THEN
							UPDATE accounts SET balance=(
								SELECT balance - (
									CASE
										WHEN '%[4]s'='deposit' THEN %[3]f::numeric
										WHEN '%[4]s'='withdraw' THEN -1 * %[3]f::numeric
										ELSE %[3]f::numeric
									END
								)
								FROM accounts WHERE account_num='%[1]s'
							)
							WHERE account_num='%[1]s';
						END IF;
					END
					$do$
					`,
					source,
					recipient,
					amount,
					transactionType,
				),
			)

			// Check for error and return if any
			if err != nil {
				return fmt.Errorf("Failed to complete this transaction: %v", err)
			}

			// Success, return nil to indicate the user has been added
			return nil
		})
		if err != nil {
			AddFlash(r, w, "e"+err.Error())
			http.Redirect(w, r, "/make-transaction", http.StatusSeeOther)
			return
		}

		// Flash message after successful insertion
		AddFlash(r, w, fmt.Sprintf("s%s of $%.2f completed successfully!", strings.Title(transactionType), amount))

		// Respond with a success message
		http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
	}

	// Quality of life improvement would be to somehow persist the form data for a retry
	// Render the make transaction form (in case of GET request or on error)
	RenderTemplate(w, "depositwithdraw.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
}

func listPotentialEmails(w http.ResponseWriter, r *http.Request) {
	profileType, loggedIn := checkLoggedIn(r, w)
	if !loggedIn {
		http.Error(w, "Unauthorized request", http.StatusUnauthorized)
		return
	}
	if profileType != "employee" {
		http.Error(w, "Unauthorized request", http.StatusUnauthorized)
		return
	}
	customerEmail := r.URL.Query().Get("email") + "%" //% is used to search for emails that start with the given email
	var potential_emails []string
	err := OpenDBConnection(func(conn *pgxpool.Pool) error {
		query := `SELECT email FROM profiles WHERE email LIKE $1 AND profile_type = 'customer' ORDER BY email LIMIT 20`
		rows, err := conn.Query(context.Background(), query, customerEmail)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var potential_email string
			if err := rows.Scan(&potential_email); err != nil {
				http.Error(w, "Server error", http.StatusInternalServerError)
				return fmt.Errorf("could not scan row: %v", err)
			}
			potential_emails = append(potential_emails, potential_email)
		}
		return nil
	})
	if err != nil {
		handle(err) //I think this is fine, not sure what errors could cause this
	}
	potential_emails_JSON, err := json.Marshal(potential_emails)
	if err != nil {
		handle(err, "Failed to generate JSON")
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write(potential_emails_JSON)
}

func forgotEmail(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "forgotemail.html")
}

func verifyEmailToRecover(w http.ResponseWriter, r *http.Request) {
	// Parse form values
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Unable to process form data", http.StatusBadRequest)
		return
	}

	fname := r.FormValue("fname")
	lname := r.FormValue("lname")
	dob := r.FormValue("dob")

	log.Printf("Received user info: fname=%s, lname=%s, dob=%s\n", fname, lname, dob)

	// Open database connection using OpenDBConnection
	err = OpenDBConnection(func(conn *pgxpool.Pool) error {
		// Query the database for the user
		query := `SELECT email FROM profiles WHERE first_name = $1 AND last_name = $2 AND date_of_birth = $3`
		var email string
		err := conn.QueryRow(context.Background(), query, fname, lname, dob).Scan(&email)

		// Handle case where no rows are found
		if err != nil {
			AddFlash(r, w, "eInformation not linked to an existing account.")
			RenderTemplate(w, "forgotemail.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
			return nil
		}

		// If we got here, it means the email was found
		// Mask the email
		emailParts := strings.Split(email, "@")
		var maskedEmail string
		if len(emailParts) > 1 {
			username := emailParts[0]
			domain := emailParts[1]
			if len(username) > 1 {
				username = string(username[0]) + strings.Repeat("*", len(username)-1)
			}
			maskedEmail = username + "@" + domain
		}

		log.Println("Masked email:", maskedEmail)

		// Render template with masked email
		RenderTemplate(w, "verifyemailtorecover.html", pongo2.Context{"MaskedEmail": maskedEmail})

		return nil
	})

	// If there was any issue in opening the database connection, log it.
	if err != nil {
		log.Println("Error in OpenDBConnection callback:", err)
	}
}

func postRecoveredEmail(w http.ResponseWriter, r *http.Request) {
	RenderTemplate(w, "postrecoveredemail.html")
}
