package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/tunedmystic/authsolo"
)

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, fmt.Sprintf("path %v not found", r.URL.Path), http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, htmlMenu+"<h1>the index page</h1>")
}

func handleAccount(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, htmlMenu+"<h1>the account page</h1>")
}

func handleNews(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, htmlMenu+"<h1>the news page</h1>")
}

var htmlMenu string = `
	<p>
		<a href="/">Home</a>
		<a href="/account">Account</a>
		<a href="/news">News</a>
		<a href="/login">Login</a>
		<a href="/logout">Logout</a>
	</p>`

func main() {
	r := http.NewServeMux()
	auth := authsolo.Init("mypassword") // 1. Initialize middleware.
	auth.RegisterHandlers(r)            // 2. Register auth handlers.

	r.HandleFunc("/", handleIndex)
	r.HandleFunc("/account", auth.Apply(handleAccount)) // 3. Wrap handlers.
	r.HandleFunc("/news", handleNews)

	fmt.Println("running server ...")
	log.Fatal(http.ListenAndServe("localhost:8000", r))
}
