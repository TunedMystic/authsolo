package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/tunedmystic/authsolo"
)

var menuLinks string = `
	<p>
		<a href="/">Home</a>
		<a href="/dashboard">Dashboard</a>
		<a href="/about">About</a>
		<a href="/login">Login</a>
		<a href="/logout">Logout</a>
	</p>`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "path %v custom 404", r.URL.Path)
		return
	}
	html := "<h1>the index page</h1>" + menuLinks
	fmt.Fprint(w, html)
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	html := "<h1>the about page</h1>" + menuLinks
	fmt.Fprint(w, html)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	html := "<h1>the dashboard page</h1>" + menuLinks
	fmt.Fprint(w, html)
}

func main() {
	// r := mux.NewRouter()
	r := http.NewServeMux()
	auth := authsolo.Init("mypassword")

	r.HandleFunc("/", indexHandler)
	r.HandleFunc("/about", aboutHandler)
	r.HandleFunc("/dashboard", auth.Apply(dashboardHandler))
	// r.PathPrefix("").Handler(auth.Routes())
	// r.Handle("/auth/", http.StripPrefix("/auth", auth.Routes()))
	r.HandleFunc("/login", auth.HandleLogin)
	r.HandleFunc("/logout", auth.HandleLogout)

	log.Fatal(http.ListenAndServe("localhost:8000", r))
}
