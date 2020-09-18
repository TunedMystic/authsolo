package authsolo

import (
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func Test_GetHash(t *testing.T) {
	type test struct {
		text     string
		expected string
	}

	tests := []test{
		{"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"hi", "c22b5f9178342609428d6f51b2c5af4c0bde6a42"},
		{"password", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"},
	}

	for _, testItem := range tests {
		t.Run(testItem.text, func(t *testing.T) {
			assertEqual(t, getHash(testItem.text), testItem.expected)
		})
	}
}

func Test_Init(t *testing.T) {
	a := Init("password")

	assertEqual(t, a.hash, "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
	assertEqual(t, a.loginURL, "/login")
	assertEqual(t, a.afterLogin, "/")
	assertEqual(t, a.nextParam, "next")
	assertEqual(t, a.cookieName, "user")
}

func Test_Login(t *testing.T) {
	a := Init("password")
	w := httptest.NewRecorder()

	a.Login(w, a.hash)

	// Get the cookie from the ResponseWriter.
	cookie := w.Result().Cookies()[0]

	assertEqual(t, cookie.Name, "user")
	assertEqual(t, cookie.Value, "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
	assertEqual(t, cookie.MaxAge, 14400)
	assertEqual(t, cookie.HttpOnly, true)
	assertEqual(t, cookie.SameSite, http.SameSiteStrictMode)
}

func Test_Logout(t *testing.T) {
	a := Init("password")
	w := httptest.NewRecorder()

	a.Logout(w)

	// Get the cookie from the ResponseWriter.
	cookie := w.Result().Cookies()[0]

	// Check cookie values.
	assertEqual(t, cookie.Name, "user")
	assertEqual(t, cookie.Value, "")
	assertEqual(t, cookie.MaxAge, -1)
	assertEqual(t, cookie.HttpOnly, true)
	assertEqual(t, cookie.SameSite, http.SameSiteStrictMode)
}

func Test_IsAuthenticated(t *testing.T) {
	a := Init("password")
	w := httptest.NewRecorder()

	a.Login(w, a.hash)

	// Add cookie to the Request.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(w.Result().Cookies()[0])

	assertEqual(t, a.IsAuthenticated(r), true)
}

func Test_IsAuthenticated__fails_when_cookie_not_set(t *testing.T) {
	a := Init("password")
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	assertEqual(t, a.IsAuthenticated(r), false)
}

func Test_IsAuthenticated__fails_when_hash_mismatch(t *testing.T) {
	a := Init("password")
	w := httptest.NewRecorder()

	a.Login(w, a.hash)

	// Set bad cookie value.
	cookie := w.Result().Cookies()[0]
	cookie.Value = "bad-hash"

	// Add cookie to the Request.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)

	assertEqual(t, a.IsAuthenticated(r), false)
}

func Test_LoginFormHTML(t *testing.T) {
	a := Init("password")
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	expectedLoginForm := `
		<form class="login-form" method="post" action="/login">
			<input type="password" placeholder="password" name="password">
			<input type="hidden" name="next" value="/">
			<button type="submit">Login</button>
		</form>`

	loginForm := a.LoginFormHTML(r)

	assertEqual(t, compress(loginForm), compress(expectedLoginForm))
}

func Test_LoginFormHTML__custom_next_param(t *testing.T) {
	a := Init("password")
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	// Add query params to the Request.
	q := url.Values{}
	q.Add("next", "/dashboard")
	r.URL.RawQuery = q.Encode()

	expectedLoginForm := `
		<form class="login-form" method="post" action="/login">
			<input type="password" placeholder="password" name="password">
			<input type="hidden" name="next" value="/dashboard">
			<button type="submit">Login</button>
		</form>`

	loginForm := a.LoginFormHTML(r)

	assertEqual(t, compress(loginForm), compress(expectedLoginForm))
}

func Test_LoginFormHTML__rendering_error(t *testing.T) {
	a := Init("password")
	a.loginFormTemplate = template.Must(template.New("").Parse("{{.BadTemplateValue}}"))

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	loginForm := a.LoginFormHTML(r)

	assertEqual(t, loginForm, "")
}

func Test_HandleLogin_Get(t *testing.T) {
	a := Init("password")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	expectedLoginForm := `
		<html>
		<form class="login-form" method="post" action="/login">
			<input type="password" placeholder="password" name="password">
			<input type="hidden" name="next" value="/">
			<button type="submit">Login</button>
		</form>
		</html>`

	http.HandlerFunc(a.HandleLogin).ServeHTTP(w, r)

	body := w.Body.String()
	assertEqual(t, compress(body), compress(expectedLoginForm))
}

func Test_HandleLogin_Get__already_authenticated(t *testing.T) {
	a := Init("password")
	ww := httptest.NewRecorder()

	a.Login(ww, a.hash)

	// Add cookie to the Request.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(ww.Result().Cookies()[0])

	w := httptest.NewRecorder()

	http.HandlerFunc(a.HandleLogin).ServeHTTP(w, r)

	// When user is already authenticated, navigating to the
	// login URL should redirect them to the afterLogin URL.

	assertEqual(t, w.Code, http.StatusFound)

	// Check redirect url location
	url, err := w.Result().Location()
	assertEqual(t, err, nil)
	assertEqual(t, url.Path, a.afterLogin)
}

func Test_HandleLogin_Post(t *testing.T) {
	a := Init("supersecret")
	w := httptest.NewRecorder()

	reader := strings.NewReader("password=supersecret")
	r := httptest.NewRequest(http.MethodPost, "/", reader)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	http.HandlerFunc(a.HandleLogin).ServeHTTP(w, r)

	assertEqual(t, w.Code, http.StatusFound)

	// Check redirect url location
	url, err := w.Result().Location()
	assertEqual(t, err, nil)
	assertEqual(t, url.Path, a.afterLogin)

	// Check cookie value
	cookie := w.Result().Cookies()[0]
	assertEqual(t, cookie.Value, a.hash)
}

func Test_HandleLogin_Post__custom_next_param(t *testing.T) {
	a := Init("supersecret")

	type test struct {
		next          string
		redirLocation string
	}

	tests := []test{
		{"", "/"},
		{a.loginURL, "/"},
		{"/dashboard", "/dashboard"},
	}

	getSubTestFunc := func(testItem test) TestFunc {
		return func(t *testing.T) {
			reader := strings.NewReader("password=supersecret")
			r := httptest.NewRequest(http.MethodPost, "/", reader)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			// Add query params to the Request.
			q := url.Values{}
			q.Add("next", testItem.next)
			r.URL.RawQuery = q.Encode()

			w := httptest.NewRecorder()

			http.HandlerFunc(a.HandleLogin).ServeHTTP(w, r)

			// When user is successfully authenticated, they should
			// be redirected to the afterLogin destination.

			assertEqual(t, w.Code, http.StatusFound)

			// Check redirect url location
			url, err := w.Result().Location()
			assertEqual(t, err, nil)
			assertEqual(t, url.Path, testItem.redirLocation)

			// Check cookie value
			cookie := w.Result().Cookies()[0]
			assertEqual(t, cookie.Value, a.hash)
		}
	}

	for _, testItem := range tests {
		testName := fmt.Sprintf("[%v=%v]?", testItem.next, testItem.redirLocation)
		subTestFunc := getSubTestFunc(testItem)
		t.Run(testName, subTestFunc)
	}
}

func Test_HandleLogin_Post__invalid_password(t *testing.T) {
	a := Init("supersecret")
	w := httptest.NewRecorder()

	reader := strings.NewReader("password=badpassword")
	r := httptest.NewRequest(http.MethodPost, "/", reader)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	http.HandlerFunc(a.HandleLogin).ServeHTTP(w, r)

	assertEqual(t, w.Code, http.StatusBadRequest)
}

func Test_HandleLogout(t *testing.T) {
	a := Init("password")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	http.HandlerFunc(a.HandleLogout).ServeHTTP(w, r)

	assertEqual(t, w.Code, http.StatusFound)

	// Check cookie value
	cookie := w.Result().Cookies()[0]
	assertEqual(t, cookie.Value, "")
	assertEqual(t, cookie.MaxAge, -1)
}

func Test_Apply(t *testing.T) {
	a := Init("password")
	ww := httptest.NewRecorder()

	a.Login(ww, a.hash)

	// Add cookie to the Request.
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.AddCookie(ww.Result().Cookies()[0])

	// Dummy handler that will be wrapped with the auth logic.
	handlerReached := false
	h := func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
	}

	w := httptest.NewRecorder()

	http.HandlerFunc(a.Apply(h)).ServeHTTP(w, r)

	assertEqual(t, w.Code, http.StatusOK)
	assertEqual(t, handlerReached, true)
}

func Test_Apply__auth_failed(t *testing.T) {
	a := Init("password")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	// Dummy handler that will be wrapped with the auth logic.
	handlerReached := false
	h := func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
	}

	http.HandlerFunc(a.Apply(h)).ServeHTTP(w, r)

	assertEqual(t, w.Code, http.StatusFound)
	assertEqual(t, handlerReached, false)
}

func Test_Routes(t *testing.T) {
	a := Init("password")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	authRoutes := a.Routes()

	http.Handler(authRoutes).ServeHTTP(w, r)
}

// ------------------------------------------------------------------
// Test Helpers
// ------------------------------------------------------------------

type TestFunc func(*testing.T)

// compress removes whitespaces and newlines from the given text.
func compress(text string) string {
	s := []string{}

	for _, item := range strings.Split(text, "\n") {
		s = append(s, strings.TrimSpace(item))
	}

	return strings.Join(s, "")
}

// assertEqual checks if values are equal.
func assertEqual(t *testing.T, a interface{}, expected interface{}) {
	if a == expected {
		return
	}

	// Get the filename + line of where the assertion failed.
	_, filename, line, _ := runtime.Caller(1)
	fmt.Printf("%s:%d expected %v (type %v), got %v (type %v)\n", filepath.Base(filename), line, expected, reflect.TypeOf(expected), a, reflect.TypeOf(a))
	t.FailNow()
}
