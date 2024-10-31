package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var host string
var port string
var env map[string]string = readEnv(".env")

type Test struct {
	Col1 string
	Col2 int
}

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

	// Read from db
	err := OpenDBConnection(func(conn *pgxpool.Pool) error {
		rows, _ := conn.Query(context.Background(), "SELECT * FROM test")
		res, err := pgx.CollectRows(rows, pgx.RowToStructByName[Test])
		handle(err, "CollectRows failed")

		// Print out each row and its values
		for _, r := range res {
			fmt.Printf("%s, %d\n", r.Col1, r.Col2)
		}
		fmt.Println(len(res))
		return nil
	})
	if err != nil {
		panic(err)
	}

	http.ServeFile(w, r, "./templates/index.html")
}

func login(w http.ResponseWriter, r *http.Request) {
	// TODO: serve a login page
	fmt.Fprint(w, "<h1>Login</h1>")
}
