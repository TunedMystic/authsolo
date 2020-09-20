package main

import (
	"fmt"
	"net/http"

	"github.com/tunedmystic/authsolo"
)

func handleIndex(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "the index page")
}

func handleAccount(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "the account page")
}

func handleNews(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "the news page")
}

func main() {
	r := http.NewServeMux()
	auth := authsolo.Init("mypassword") // 1. Initialize middleware.

	r.HandleFunc("/", handleIndex)
	r.HandleFunc("/account", auth.Apply(handleAccount)) // 2. Wrap handlers.
	r.HandleFunc("/news", handleNews)

	http.ListenAndServe("localhost:8000", auth.WithRouter(r)) // 3. Register authsolo's handlers.
}
