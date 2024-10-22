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

	log.Printf("Running on http://%s:%d (Press CTRL+C to quit)", hostname, port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./templates/index.html")
}
