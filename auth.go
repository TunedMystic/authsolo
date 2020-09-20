package authsolo

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"html"
	"html/template"
	"net/http"
)

// Auth is a middleware that provides password authentication.
// It also contains custom handlers (login, logout) for basic auth flow.
type Auth struct {
	hash              string
	loginURL          string
	logoutURL         string
	loginSuccessURL   string
	nextParam         string
	cookieName        string
	loginFormTemplate *template.Template
}

// New creates a new Auth instance with the supplied password.
func New(password string) *Auth {
	a := Auth{
		hash:              getHash(password),
		loginURL:          "/login",
		logoutURL:         "/logout",
		loginSuccessURL:   "/",
		nextParam:         "next",
		cookieName:        "user",
		loginFormTemplate: template.Must(template.New("").Parse(loginFormHTML)),
	}
	return &a
}

// Login creates a cookie with the hashed password, and sets it on the ResponseWriter.
func (a *Auth) Login(w http.ResponseWriter, hashedPw string) {
	cookie := http.Cookie{
		Name:     a.cookieName,
		Value:    hashedPw,
		MaxAge:   60 * 60 * 4, // 4 hours
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &cookie)
}

// Logout removes the cookie from the ResponseWriter.
func (a *Auth) Logout(w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:     a.cookieName,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &cookie)
}

// IsAuthenticated checks if a user is logged in. It checks an http.Request
// to see if the cookie's hash matches the one stored in the middleware.
func (a *Auth) IsAuthenticated(r *http.Request) bool {
	c, err := r.Cookie(a.cookieName)

	// If no cookie is set, then user is not authenticated.
	if err != nil {
		return false
	}

	// If the hash value does not match, then user is not authenticated.
	if c.Value != a.hash {
		return false
	}

	return true
}

// Users can specify where they want to be redirected to after they successfully login.
// This is called the loginSuccessURL, and is stored on the request as a query param `?next=`.
func (a *Auth) getLoginSuccessURL(r *http.Request) string {
	url := r.Form.Get(a.nextParam)

	// If the parsed url is login/logout or is empty,
	// then fallback to the loginSuccessURL.
	if url == "" || url == a.loginURL || url == a.logoutURL {
		url = a.loginSuccessURL
	}

	url = html.EscapeString(url) // :)

	return url
}

// LoginFormHTML creates and returns a login form with the resolved loginSuccessURL.
func (a *Auth) LoginFormHTML(r *http.Request) string {
	url := a.getLoginSuccessURL(r)

	data := struct {
		LoginURL        string
		LoginSuccessURL string
		NextParam       string
	}{
		a.loginURL,
		url,
		a.nextParam,
	}

	var b bytes.Buffer
	if err := a.loginFormTemplate.Execute(&b, data); err != nil {
		return ""
	}

	return b.String()
}

// HandleLogin handles the logic for logging in a user.
// On GET, login form is shown.
// On POST, cookie is generated if passwords match.
func (a *Auth) HandleLogin(w http.ResponseWriter, r *http.Request) {

	// Parse request data, so that the subsequent methods
	// have access to it via `r.Form`.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid data", http.StatusBadRequest)
		return
	}

	if r.Method == "POST" {
		a.handleLoginPost(w, r)
		return
	}

	a.handleLoginGet(w, r)
}

// handleLoginGet shows the login form if the user is not yet logged in.
// If the user is logged in, then it redirects to the default loginSuccessURL.
func (a *Auth) handleLoginGet(w http.ResponseWriter, r *http.Request) {

	// If user is already authenticated then redirect to the loginSuccessURL.
	if a.IsAuthenticated(r) {
		http.Redirect(w, r, a.loginSuccessURL, http.StatusFound)
	}

	tpl := template.Must(template.New("").Parse("<html>{{.}}</html>"))
	tpl.Execute(w, template.HTML(a.LoginFormHTML(r)))
}

// handleLoginPost parses the login form and creates the cookie if the password match.
// After successful login, it redirects to the resolved loginSuccessURL.
func (a *Auth) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	hashedPw := getHash(r.Form.Get("password"))

	// Passwords match, so perform the login and redirect to the loginSuccessURL.
	if hashedPw == a.hash {
		a.Login(w, hashedPw)
		http.Redirect(w, r, a.getLoginSuccessURL(r), http.StatusFound)
		return
	}

	http.Error(w, "invalid login", http.StatusBadRequest)
}

// HandleLogout handles the logic for logging out a user.
// The cookie is cleared and it redirects to the configured loginURL.
func (a *Auth) HandleLogout(w http.ResponseWriter, r *http.Request) {
	a.Logout(w)
	http.Redirect(w, r, a.loginURL, http.StatusFound)
}

// Solo provides the auth functionality for an http.HandlerFunc.
func (a *Auth) Solo(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Run the auth checking logic, using `next` as an http.Handler.
		a.SoloH(next).ServeHTTP(w, r)
	})
}

// SoloH provides the auth functionality for an http.Handler.
// If user is authenticated, then allow the `next` handler to execute.
// If user is NOT authenticated, then redirect to the login page.
func (a *Auth) SoloH(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// If user is not authenticated, then redirect to login.
		if !a.IsAuthenticated(r) {
			// Clear bad cookie.
			a.Logout(w)

			// Redirect to login
			loginURL := fmt.Sprintf("%v?%v=%v", a.loginURL, a.nextParam, r.URL.Path)
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Handler wraps an http.Handler and injects the internal handlers for
// logging in and logging out.
func (a *Auth) Handler(h http.Handler) http.Handler {

	// Wrap the handler with Auth's internal handlers.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == a.loginURL {
			a.HandleLogin(w, r)
			return
		}
		if r.URL.Path == a.logoutURL {
			a.HandleLogout(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// getHash hashes and returns the given text.
func getHash(text string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(text)))
}

// loginFormHTML is the form used for logging in.
var loginFormHTML string = `
<form class="login-form" method="post" action="{{.LoginURL}}">
	<input type="password" placeholder="password" name="password">
	<input type="hidden" name="{{.NextParam}}" value="{{.LoginSuccessURL}}">
	<button type="submit">Login</button>
</form>`
