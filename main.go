package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
)

func (app *application) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if ok {
		// Calculate SHA-256 hashes for the provided and expected
		// usernames and passwords.
		usernameHash := sha256.Sum256([]byte(username))
		passwordHash := sha256.Sum256([]byte(password))
		expectedUsernameHash := sha256.Sum256([]byte(app.auth.username))
		expectedPasswordHash := sha256.Sum256([]byte(app.auth.password))
		// Use the subtle.ConstantTimeCompare() function to check if 
		// the provided username and password hashes equal the  
		// expected username and password hashes. ConstantTimeCompare
		// will return 1 if the values are equal, or 0 otherwise. 
		// Importantly, we should to do the work to evaluate both the 
		// username and password before checking the return values to 
		// avoid leaking information.
		usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
		passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

		// If the username and password are correct, then call
		// the next handler in the chain. Make sure to return 
		// afterwards, so that none of the code below is run.
		if usernameMatch && passwordMatch {
			next.ServeHTTP(w, r)
			return
		}
	}
	// If the Authentication header is not present, is invalid, or the
		// username or password is wrong, then set a WWW-Authenticate 
		// header to inform the client that we expect them to use basic
		// authentication and send a 401 Unauthorized response.
		w.Header().Set("WWW-Authenticate", `Basic realm="test", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		})
}

type application struct {
	auth struct {
		username string
		password string
	}
}

func main() {
	app := new(application)
	err := godotenv.Load()
	if err != nil {
	log.Fatalf("Error loading .env file")
	}

	app.auth.username = os.Getenv("AUTH_USERNAME")
	app.auth.password = os.Getenv("AUTH_PASSWORD")

	if app.auth.username == "" {
		log.Fatal("basic auth username/password must be provided")
	} 
	if app.auth.password == "" {
		log.Fatal("basic auth username/password must be provided")
	}

	http.HandleFunc("/", app.homeHandler)
	http.HandleFunc("/unprotected", app.unprotectedHandler)
	http.HandleFunc("/protected", app.basicAuth(app.protectedHandler))

	srv := &http.Server{
			Addr:         ":8080",
			Handler:      nil,
			IdleTimeout:  time.Minute,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
		}

	log.Printf("starting server on https://localhost%s", srv.Addr)
	err = srv.ListenAndServeTLS("./localhost.pem", "./localhost-key.pem")
	log.Fatal(err)

}

func (app *application) homeHandler(w http.ResponseWriter, r *http.Request) {
	//tmpl := template.New("home")
	tmpl, err := template.ParseFiles("index.html")
	if err != nil {
		log.Fatal(err)
	}
	err = tmpl.Execute(w, nil); if err != nil {
		log.Fatal(err)
	}
}

func (app *application) protectedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "This is the protected handler")
}

func (app *application) unprotectedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "This is the unprotected handler")
}