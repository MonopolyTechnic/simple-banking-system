package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"github.com/MonopolyTechnic/simple-banking-system/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/gorilla/sessions"
	"bytes"
	"time"
)

var (
	host      string
	port      string
	env       map[string]string = readEnv(".env")
	store     = sessions.NewCookieStore([]byte("your-secret-key")) // Change this to a secure key
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
	http.HandleFunc("/login", login)
	http.HandleFunc("/twofa", twofa)

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
		rows, _ := conn.Query(context.Background(), "SELECT first_name, last_name FROM employees")
		res, err := pgx.CollectRows(rows, pgx.RowToStructByNameLax[models.Employee])
		handle(err, "CollectRows failed")

		// Print out each row and its values
		for _, r := range res {
			fmt.Println(r.Id)
			fmt.Println(r.FirstName.String)
			fmt.Println(r.MiddleName.String)
			fmt.Println(r.LastName.String)
			fmt.Println(r.BillingAddress.String)
			fmt.Println(r.DateOfBirth.Time)
			fmt.Println(r.PasswordHash.Bytes)
		}
		fmt.Println(len(res))
		return nil
	})
	handle(err)

	http.ServeFile(w, r, "./templates/index.html")
}

func login(w http.ResponseWriter, r *http.Request) {
	// TODO: serve a login page
	fmt.Fprint(w, "<h1>Login</h1>")
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

		var out bytes.Buffer
		cmd := exec.Command("python3", "twofasendcode.py", phone_number, phone_carrier)
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			http.Error(w, "Failed to send code", http.StatusInternalServerError)
			return
		}
		actualCode := out.String()
		session.Values["actualCode"] = actualCode // Store the code in the session
		err = session.Save(r, w) // Save the session
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
			http.Error(w, "Invalid code", http.StatusUnauthorized)//change this for a second attempt?
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
