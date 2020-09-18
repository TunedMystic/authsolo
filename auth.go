package authsolo

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"html"
	"html/template"
	"net/http"
)

// Auth struct
type Auth struct {
	hash              string
	loginURL          string
	afterLogin        string
	nextParam         string
	cookieName        string
	loginFormTemplate *template.Template
}

// Init function
func Init(password string) *Auth {
	a := Auth{
		hash:              getHash(password),
		loginURL:          "/login",
		afterLogin:        "/",
		nextParam:         "next",
		cookieName:        "user",
		loginFormTemplate: template.Must(template.New("").Parse(loginFormHTML)),
	}
	return &a
}

// Login method
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

// Logout method
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

// IsAuthenticated method
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

// LoginFormHTML method
func (a *Auth) LoginFormHTML(r *http.Request) string {
	afterLogin := r.URL.Query().Get("next")

	if afterLogin == "" {
		afterLogin = a.afterLogin
	}

	afterLogin = html.EscapeString(afterLogin)

	data := struct {
		LoginURL   string
		NextParam  string
		AfterLogin string
	}{
		a.loginURL,
		a.nextParam,
		afterLogin,
	}

	var b bytes.Buffer
	if err := a.loginFormTemplate.Execute(&b, data); err != nil {
		return ""
	}

	return b.String()
}

// HandleLogin method
func (a *Auth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		a.HandleLoginPost(w, r)
		return
	}

	a.HandleLoginGet(w, r)
	return
}

// HandleLoginGet method
func (a *Auth) HandleLoginGet(w http.ResponseWriter, r *http.Request) {

	// If user is already authenticated then redirect to the destination.
	if a.IsAuthenticated(r) {
		http.Redirect(w, r, a.afterLogin, http.StatusFound)
	}

	tpl := template.Must(template.New("").Parse("<html>{{.}}</html>"))
	tpl.Execute(w, template.HTML(a.LoginFormHTML(r)))
}

// HandleLoginPost method
func (a *Auth) HandleLoginPost(w http.ResponseWriter, r *http.Request) {

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid data", http.StatusBadRequest)
		return
	}

	hashedPw := getHash(r.Form.Get("password"))

	if hashedPw == a.hash {
		a.Login(w, hashedPw)

		// Determine where to redirect to. If afterLogin is
		// the login url or is empty, then redirect to the
		// fallback destination, which is '/'.
		afterLogin := r.Form.Get("next")
		if afterLogin == "" || afterLogin == a.loginURL {
			afterLogin = "/"
		}

		http.Redirect(w, r, afterLogin, http.StatusFound)
		return
	}

	http.Error(w, "invalid login", http.StatusBadRequest)
}

// HandleLogout method
func (a *Auth) HandleLogout(w http.ResponseWriter, r *http.Request) {
	a.Logout(w)
	http.Redirect(w, r, a.loginURL, http.StatusFound)
}

// Apply method
func (a *Auth) Apply(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// If user is not authenticated, then redirect to login.
		if !a.IsAuthenticated(r) {
			// Clear bad cookie.
			a.Logout(w)

			// Redirect to login
			loginURL := fmt.Sprintf("%v?%v=%v", a.loginURL, a.nextParam, r.URL.Path)
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		// User is authenticated. Move along.
		next(w, r)
	}
}

// Routes method
func (a *Auth) Routes() *http.ServeMux {
	router := http.NewServeMux()
	router.HandleFunc("/login", a.HandleLogin)
	router.HandleFunc("/logout", a.HandleLogout)
	return router
}

func getHash(text string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(text)))
}

var loginFormHTML string = `
<form class="login-form" method="post" action="{{.LoginURL}}">
	<input type="password" placeholder="password" name="password">
	<input type="hidden" name="{{.NextParam}}" value="{{.AfterLogin}}">
	<button type="submit">Login</button>
</form>`
