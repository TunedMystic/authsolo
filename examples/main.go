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
	auth := authsolo.New("mypassword") // 1. create middleware

	r.HandleFunc("/", handleIndex)
	r.HandleFunc("/account", auth.Solo(handleAccount)) // 2. protect handlers
	r.HandleFunc("/news", handleNews)

	http.ListenAndServe("localhost:8000", auth.Handler(r)) // 3. inject internal handlers
}
