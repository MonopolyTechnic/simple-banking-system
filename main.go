package main

import (
	"fmt"
	"log"
	"net/http"
)

var hostname string
var port int

func main() {
	// Show file and line number in logs
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Env vars (for now)
	hostname = "127.0.0.1"
	port = 5000

	// Serve static content
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Routes
	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)

	log.Printf("Running on http://%s:%d (Press CTRL+C to quit)", hostname, port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	// For some reason Go's net/http interprets / as a wild card path
	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		// TODO: Serve a custom 404 page here instead
		fmt.Fprint(w, "<h1>Page not found.</h1>")
		return
	}
	http.ServeFile(w, r, "./templates/index.html")
}

func login(w http.ResponseWriter, r *http.Request) {
	// TODO: serve a login page
	fmt.Fprint(w, "<h1>Login</h1>")
}
