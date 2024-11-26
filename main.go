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
	config      map[string]string     = readEnv("config.env")
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
	http.HandleFunc("/settings", settings)
	http.HandleFunc("/user-dashboard", userDashboard)
	http.HandleFunc("/transaction-history", transactionHistory)
	http.HandleFunc("/transfer", transfer)
	http.HandleFunc("/notifications", notifications)
	http.HandleFunc("/change-status", changeStatus)

	pongo2.Globals.Update(pongo2.Context{"global_styles": GetGlobalStyles()})

	pongo2.RegisterFilter("getFlashType", getFlashType)
	pongo2.RegisterFilter("getFlashMessage", getFlashMessage)
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

	RenderTemplate(w, "index.html", pongo2.Context{"logo": config["LOGO"]})
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
		AccountNum    string
		AccountType   string
		Balance       float64
		AccountStatus string
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
			`SELECT account_num, account_type, balance, account_status FROM accounts WHERE primary_customer_id = $1 OR secondary_customer_id = $1`,
			id, // Use the customer ID obtained earlier
		)
		if err != nil {
			return fmt.Errorf("Invalid account: %s", id)
		}
		defer rows.Close()

		for rows.Next() {
			var account struct {
				AccountNum    string
				AccountType   string
				Balance       float64
				AccountStatus string
			}
			if err := rows.Scan(&account.AccountNum, &account.AccountType, &account.Balance, &account.AccountStatus); err != nil {
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
	//log.Printf("accounts: %+v", accounts)
	RenderTemplate(w, "accounts_dashboard.html", pongo2.Context{"acclist": accounts, "flashes": RetrieveFlashes(r, w), "fname": name})
}

func notifications(w http.ResponseWriter, r *http.Request) {
	profileType, loggedIn := checkLoggedIn(r, w)
	if !loggedIn {
		http.Redirect(w, r, "/login-user", http.StatusSeeOther)
		return
	}
	if profileType != "customer" {
		http.Error(w, "Unauthorized Request", http.StatusUnauthorized)
		return
	}

	// Valid sign-in session
	session, err := store.Get(r, "current-session")
	handle(err)
	val, _ := session.Values["logged-in"]
	email := val.(*LogInSessionCookie).Email

	var messages []struct {
		Title   string    `json:"Title"`
		Content string    `json:"Content"`
		Sent    time.Time `json:"Sent"`
		Seen    bool      `json:"Seen"`
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
			`SELECT title, content, sent_timestamp, seen FROM notifications WHERE target_userid = $1 ORDER BY sent_timestamp DESC`,
			id,
		)
		if err != nil {
			return fmt.Errorf("Invalid return from accounts: %s", email)
		}
		defer rows.Close()
		for rows.Next() {
			var message struct {
				Title   string    `json:"Title"`
				Content string    `json:"Content"`
				Sent    time.Time `json:"Sent"`
				Seen    bool      `json:"Seen"`
			}
			if err := rows.Scan(&message.Title, &message.Content, &message.Sent, &message.Seen); err != nil {
				return fmt.Errorf("Error scanning notification row: %v", err)
			}
			messages = append(messages, message)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("Error while iterating over notification rows: %v", err)
		}
		return nil
	})
	if err != nil {
		AddFlash(r, w, "e"+err.Error())
	}
	RenderTemplate(w, "notifications.html", pongo2.Context{"notifications": messages, "flashes": RetrieveFlashes(r, w), "fname": name})
}

func transfer(w http.ResponseWriter, r *http.Request) {
	profileType, loggedIn := checkLoggedIn(r, w)
	if !loggedIn {
		http.Redirect(w, r, "/login-user", http.StatusSeeOther)
		return
	}
	if profileType != "customer" {
		http.Error(w, "Unauthorized Request", http.StatusUnauthorized)
		return
	}

	// Valid sign-in session
	session, err := store.Get(r, "current-session")
	handle(err)
	val, _ := session.Values["logged-in"]
	email := val.(*LogInSessionCookie).Email

	var accounts []struct {
		Number  string  `json:"Number"`
		Balance float64 `json:"Balance"`
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
			`SELECT account_num, balance FROM accounts WHERE primary_customer_id = $1 OR secondary_customer_id = $1`,
			id, // Use the customer ID obtained earlier
		)

		if err != nil {
			return fmt.Errorf("Invalid return from accounts: %s", email)
		}
		defer rows.Close()

		for rows.Next() {
			var account struct {
				Number  string  `json:"Number"`
				Balance float64 `json:"Balance"`
			}
			if err := rows.Scan(&account.Number, &account.Balance); err != nil {
				return fmt.Errorf("Error scanning account row: %v", err)
			}
			accounts = append(accounts, account)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("Error while iterating over account rows: %v", err)
		}
		return nil
	})
	if err != nil {
		AddFlash(r, w, "e"+err.Error())
	}
	if r.Method == http.MethodPost {
		var userA int
		var userB sql.NullInt64
		var userC int
		var userD sql.NullInt64

		sourceAccount := r.FormValue("sourceAccount")
		destinationAccount := r.FormValue("destinationAccount")
		amountStr := r.FormValue("amount")
		amount, err := strconv.ParseFloat(amountStr, 64)
		if sourceAccount == destinationAccount {
			AddFlash(r, w, "eCannot transfer to the same account.")
			http.Redirect(w, r, "/transfer", http.StatusSeeOther)
			return //return to avoid actually doing the transfer
		}
		if err != nil {
			AddFlash(r, w, "e"+err.Error())
			http.Redirect(w, r, "/transfer", http.StatusSeeOther)
		}
		index := -1
		for i := 0; i < len(accounts); i++ {
			if accounts[i].Number == sourceAccount {
				index = i
			}
		}
		if index == -1 {
			AddFlash(r, w, "eThis shouldn't even be possible. How??")
			http.Redirect(w, r, "/transfer", http.StatusSeeOther)
		}
		currb := accounts[index].Balance
		if currb < amount {
			AddFlash(r, w, "eBalance too low to transfer this amount.")
			http.Redirect(w, r, "/transfer", http.StatusSeeOther)
		}
		err = OpenDBConnection(func(conn *pgxpool.Pool) error {
			// Query to get the customer ID for the primary customer email
			err := checkStatus(conn, sourceAccount)
			if err != nil {
				return fmt.Errorf("Account failure: %v", err)
			}
			err = checkStatus(conn, destinationAccount)
			if err != nil {
				return fmt.Errorf("Account failure: %v", err)
			}
			var dbal float64
			var tmp float64
			err = conn.QueryRow(
				context.Background(),
				`SELECT balance, primary_customer_id, secondary_customer_id FROM accounts WHERE account_num = $1`,
				destinationAccount,
			).Scan(&dbal, &userC, &userD)
			if err != nil {
				return fmt.Errorf("Destination Account does not exist.")
			}
			err = conn.QueryRow(
				context.Background(),
				`SELECT primary_customer_id, secondary_customer_id FROM accounts WHERE account_num = $1`,
				sourceAccount,
			).Scan(&userA, &userB)
			if err != nil {
				return fmt.Errorf("Source Account does not exist.")
			}
			err = conn.QueryRow(
				context.Background(),
				`UPDATE accounts SET balance = $1 WHERE account_num = $2 RETURNING balance`,
				currb-amount, sourceAccount,
			).Scan(&tmp)
			if err != nil {
				return fmt.Errorf("Bad Update: %v", err)
			}
			err = conn.QueryRow(
				context.Background(),
				`UPDATE accounts SET balance = $1 WHERE account_num = $2 RETURNING balance`,
				dbal+amount, destinationAccount,
			).Scan(&tmp)
			if err != nil {
				return fmt.Errorf("Bad Update: %v", err)
			}
			err = conn.QueryRow(
				context.Background(),
				`INSERT INTO transactions(
					source_account,
					recipient_account,
					amount,
					transaction_type,
					transaction_timestamp
				) VALUES (
					$1, $2, $3, $4, CURRENT_TIMESTAMP
				) RETURNING transaction_id`,
				sourceAccount, destinationAccount, amount, "deposit",
			).Scan(&tmp)
			if err != nil {
				return fmt.Errorf("Bad Insert into Transactions: %v", err)
			}
			return nil
		})
		if err != nil {
			AddFlash(r, w, "e"+err.Error())
		} else {
			AddFlash(r, w, "sTransfer Success")
			msg1 := fmt.Sprintf("Sent transfer of $%.2f to account #%s from #%s", amount, destinationAccount, sourceAccount)
			msg2 := fmt.Sprintf("Received transfer of $%.2f from account #%s to #%s", amount, sourceAccount, destinationAccount)
			sendNotification(userA, "Transfer", msg1)
			if userB.Valid {
				sendNotification(int(userB.Int64), "Transfer", msg1)
			}
			sendNotification(userC, "Transfer", msg2)
			if userD.Valid {
				sendNotification(int(userD.Int64), "Transfer", msg2)
			}
		}
		http.Redirect(w, r, "/transfer", http.StatusSeeOther)
	}
	RenderTemplate(w, "transfer.html", pongo2.Context{"acclist": accounts, "flashes": RetrieveFlashes(r, w), "fname": name})
}

func transactionHistory(w http.ResponseWriter, r *http.Request) {
	profileType, loggedIn := checkLoggedIn(r, w)
	if !loggedIn {
		http.Redirect(w, r, "/login-user", http.StatusSeeOther)
		return
	}
	if profileType != "customer" {
		http.Error(w, "Unauthorized Request", http.StatusUnauthorized)
		return
	}

	// Valid sign-in session
	session, err := store.Get(r, "current-session")
	handle(err)
	val, _ := session.Values["logged-in"]
	email := val.(*LogInSessionCookie).Email

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
			"SELECT first_name, profile_type, password_hash, phone_number, phone_carrier, masked_password FROM profiles WHERE email = $1 AND profile_type = $2",
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
		Email:          r.FormValue("email"),
		FirstName:      res[0].FirstName.String,
		ProfileType:    res[0].ProfileType.String,
		PhoneNumber:    res[0].PhoneNumber.String,
		PhoneCarrier:   res[0].PhoneCarrier.String,
		MaskedPassword: res[0].MaskedPassword.String,
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
			if r.URL.Query().Get("resend") == "true" {
				AddFlash(r, w, "sA new code has been sent to your phone. Please enter the new code.")
			}
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
		FirstName:    "",
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
		session, err := store.Get(r, "current-session")
		handle(err)
		val, _ := session.Values["logged-in"]
		RenderTemplate(w, "employeehomescreen.html", pongo2.Context{
			"fname":    val.(*LogInSessionCookie).FirstName,
			"bankname": config["BANK_NAME"],
			"flashes":  RetrieveFlashes(r, w),
		})
	} else {
		http.Redirect(w, r, "/user-dashboard", http.StatusSeeOther)
	}
}

func changeStatus(w http.ResponseWriter, r *http.Request) {
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
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form data", http.StatusBadRequest)
			return
		}

		// Extract the data from the form
		account_num := r.FormValue("accnum")
		targetstatus := r.FormValue("targetstatus")
		err = OpenDBConnection(func(conn *pgxpool.Pool) error {
			var tmp string
			if targetstatus == "CLOSED" {
				var bal float64
				err = conn.QueryRow(
					context.Background(),
					`SELECT balance FROM accounts WHERE account_num = $1`,
					account_num,
				).Scan(&bal)
				if bal >= 0.01 {
					return fmt.Errorf("Balance too high to close account.")
				}
			}
			err = conn.QueryRow(
				context.Background(),
				`UPDATE accounts SET account_status = $1 WHERE account_num = $2 RETURNING account_status`,
				targetstatus, account_num,
			).Scan(&tmp)
			if err != nil {
				return fmt.Errorf("Bad Update: %v", err)
			}
			return nil
		})
		if err != nil {
			AddFlash(r, w, "e"+err.Error())
			http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
			return
		} else {
			AddFlash(r, w, fmt.Sprintf("sAccount %s Status changed to %s", account_num, targetstatus))
			http.Redirect(w, r, "/employee-dashboard", http.StatusSeeOther)
			return
		}
	}
	RenderTemplate(w, "freezeaccount.html", pongo2.Context{"flashes": RetrieveFlashes(r, w)})
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
		maskedPassword := ""
		if len(password) > 0 {
			maskedPassword = string(password[0]) + strings.Repeat("*", len(password)-1)
		}
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
					password_hash,
					masked_password
				) VALUES (
					'customer', 
					$1,
					$2, 
					$3, 
					$4, 
					$5, 
					$6, 
					$7, 
					$8,
					$9
				);`,
				firstName,
				lastName,
				email,
				dob,            // Include Date of Birth
				billingAddress, // Include Billing Address
				phoneNum,
				carrier,
				passwordHash,
				maskedPassword,
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
						balance,
						account_status
					) VALUES (
						$1, $2, $3, $4, 'OPEN'
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
						balance,
						account_status
					) VALUES (
						$1, $2, $3, $4, $5, 'OPEN'
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
			"SELECT account_num, primary_customer_id, secondary_customer_id, account_type, balance, account_status FROM accounts WHERE primary_customer_id = $1 OR secondary_customer_id = $1",
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
		AccountStatus       string  `json:"accountStatus"`
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
		if item.AccountStatus.Status == pgtype.Present {
			jsonData[i].AccountStatus = item.AccountStatus.String
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

		var userA int
		var userB sql.NullInt64

		// Create the transaction and update the account balance
		// Postgres only supports positional args ($1, $2, etc.) for 1 query, so must use fmt.Sprintf instead
		err = OpenDBConnection(func(conn *pgxpool.Pool) error {
			err := conn.QueryRow(
				context.Background(),
				`SELECT primary_customer_id, secondary_customer_id FROM accounts WHERE account_num = $1`,
				recipient,
			).Scan(&userA, &userB)
			if err != nil {
				return fmt.Errorf("Failed to retrieve recipient account: %v", err)
			}
			err = checkStatus(conn, recipient)
			if err != nil {
				return fmt.Errorf("Account failure: %v", err)
			}
			_, err = conn.Exec(
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

		// Send notification to each user
		msg := "Error"
		if transactionType == "deposit" {
			msg = fmt.Sprintf("Deposit of $%.2f to account #%s", amount, recipient)
		}
		if transactionType == "withdraw" {
			msg = fmt.Sprintf("Withdrawal of $%.2f from account #%s", amount, recipient)
		}
		sendNotification(userA, "Transaction", msg)
		if userB.Valid {
			sendNotification(int(userB.Int64), "Transaction", msg)
		}

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

func settings(w http.ResponseWriter, r *http.Request) {
	_, loggedIn := checkLoggedIn(r, w)
	if !loggedIn {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Retrieve session data
	session, err := store.Get(r, "current-session")
	handle(err)
	val, _ := session.Values["logged-in"]
	// Extract email and masked password directly
	userEmail := val.(*LogInSessionCookie).Email
	maskedPassword := val.(*LogInSessionCookie).MaskedPassword

	var profileType, firstName, phoneNumber string

	// Retrieve the first_name for the logged-in user using email
	err = OpenDBConnection(func(conn *pgxpool.Pool) error {
		return conn.QueryRow(
			context.Background(),
			"SELECT profile_type, first_name, phone_number FROM profiles WHERE email = $1",
			userEmail,
		).Scan(&profileType, &firstName, &phoneNumber)
	})
	if err != nil {
		// Handle the error (e.g., log or return an error message)
		log.Println("Error retrieving user data:", err)
	}

	recentLogin := time.Now().Format("2006-01-02 15:04:05")

	RenderTemplate(w, "settings.html", pongo2.Context{
		"profileType":    profileType,
		"fname":          firstName,
		"recentLogin":    recentLogin,
		"email":          userEmail,
		"phoneNumber":    phoneNumber,
		"maskedPassword": maskedPassword,
		"bankname":       config["BANK_NAME"],
	})
}
