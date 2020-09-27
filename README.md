# authsolo

<img alt="authsolo" width="150" src="image.jpg">

![GitHub release (latest by date)](https://img.shields.io/github/v/release/tunedmystic/authsolo)
[![Build Status](https://travis-ci.com/TunedMystic/authsolo.svg?branch=master)](https://travis-ci.com/TunedMystic/authsolo)
[![codecov](https://codecov.io/gh/TunedMystic/authsolo/branch/master/graph/badge.svg)](https://codecov.io/gh/TunedMystic/authsolo)
[![Go Report Card](https://goreportcard.com/badge/github.com/tunedmystic/authsolo)](https://goreportcard.com/report/github.com/tunedmystic/authsolo)


Authsolo is a user-less authentication middleware. It provides basic auth flow for your application, and is compatible with the standard `net/http` Handler.

There are no users or sessions involved. With Authsolo you authenticate with just **one password**.

> **note**: This middleware does not follow security best practices. It was created for use in demo / side projects. You shouldn't really use this in production.

## Install

```
go get github.com/tunedmystic/authsolo
```

## Usage

Using the middleware is simple.

<br />

1) First create the middleware with the master password
```go
auth := authsolo.New("mypassword")
```

<br />

2) Then, wrap your handler functions you want protected with `.Solo` method.
```go
r.HandleFunc("/admin", auth.Solo(handleAdmin))
```

<br />

3) Lastly, wrap the router with `.Handler`. method This will inject authsolo's custom login and logout handlers.
```go
http.ListenAndServe(":8000", auth.Handler(r))
```

## Example

A simple example using the Authsolo middleware.

```go
// main.go
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

func main() {
	r := http.NewServeMux()
	auth := authsolo.New("mypassword") // 1. create middleware

	r.HandleFunc("/", handleIndex)
	r.HandleFunc("/account", auth.Solo(handleAccount)) // 2. protect handlers

	http.ListenAndServe(":8000", auth.Handler(r)) // 3. inject internal handlers
}
```

## License

MIT Licensed. See the included LICENSE file for details.
