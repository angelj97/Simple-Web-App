package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var (
	tpl       *template.Template
	db        *sql.DB
	err       error
	RegErrors string
	UserID    string
	Username  string
	Hash      string
)

var store = sessions.NewCookieStore([]byte("secret-cookie"))

func connectDb() {
	db, err = sql.Open("mysql", "root:password@tcp(localhost:3306)/userdata") // Opening connection the the database and closed inside main
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully connected to database.")
}

func main() {
	connectDb()
	defer db.Close()
	tpl = template.Must(template.ParseGlob("./static/*.gohtml")) // Storing html templates

	r := mux.NewRouter()
	fs := http.FileServer(http.Dir("./static/"))                       // File server for serving css
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs)) //
	r.HandleFunc("/", rootHandler).Methods("GET")                      //
	r.HandleFunc("/", loginAuth).Methods("POST")                       // GET for when the user first opens the website
	r.HandleFunc("/register", registerHandler).Methods("GET")          // POST for when the user sends data via form
	r.HandleFunc("/register", registerAuth).Methods("POST")            //
	r.HandleFunc("/home", homeHandler).Methods("GET")

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")   // Openning session
	untyped, ok := session.Values["notice"] // Retrieve notices from sessions
	if !ok {
		fmt.Println("not new user")
	}
	notice, _ := untyped.(string)
	if !ok {
		fmt.Println("no notice to display")
	}
	tpl.ExecuteTemplate(w, "index.gohtml", notice)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	tpl.ExecuteTemplate(w, "register.gohtml", nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")     // Openning session
	untyped, ok := session.Values["username"] // Retrieve username from sessions
	if !ok {                                  // Redirect if no user is found in the session
		http.Redirect(w, r, "/", http.StatusFound)
	}
	username, ok := untyped.(string)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
	}
	tpl.ExecuteTemplate(w, "home.gohtml", string(username))
}

func loginAuth(w http.ResponseWriter, r *http.Request) {
	var rxUsername = regexp.MustCompile("[a-zA-Z0-9._]{8,20}") // RegEx pattern for any alphanumeric, must be between 8 and 20 chars long
	username := r.PostFormValue("username")                    //
	password := r.PostFormValue("password")                    // Retrieve information from the forms
	matchU := rxUsername.Match([]byte(username))               // Compares username to RegEx pattern
	if matchU == true {
		err := db.QueryRow("SELECT hash FROM users WHERE username = ?", username).Scan(&Hash) // Searching for hash to see if the user exists
		if err != nil {
			fmt.Println("hash not found", err)
			RegErrors = "Check username and password."
		}
		if err == nil {
			err := bcrypt.CompareHashAndPassword([]byte(Hash), []byte(password)) // Compare user's password to the hash on the database
			if err != nil {
				RegErrors = "Check username and password."
				fmt.Println(err.Error())
			} else {
				session, _ := store.Get(r, "session") // If the username and password match what is on the database
				session.Values["username"] = username // this opens a new session and saves the username
				session.Save(r, w)
				http.Redirect(w, r, "/home", http.StatusFound)
			}
		}
	}
	tpl.ExecuteTemplate(w, "index.gohtml", RegErrors)
}

func registerAuth(w http.ResponseWriter, r *http.Request) {
	username := r.PostFormValue("username")   // Retrieve information from the forms
	password := r.PostFormValue("password")   //
	password2 := r.PostFormValue("password2") //
	if regValidate(username, password, password2) {
		err := db.QueryRow("SELECT UserID FROM users WHERE username = ?", username).Scan(&UserID)
		if err != sql.ErrNoRows { // If the UserID is not empty
			fmt.Println("username already exists, err:", err)
			RegErrors = "Username is already taken."
		} else { // If the UserID is empty, create a hash from the password
			var hash []byte
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				log.Fatal(err)
			}
			var insertStmt *sql.Stmt
			insertStmt, err = db.Prepare("INSERT INTO users (Username, Hash) VALUES (?, ?);") // Preparing INSERT statement for mySQL
			if err != nil {
				fmt.Println("error preparing statement:", err)
				return
			}
			defer insertStmt.Close()
			var result sql.Result
			result, err = insertStmt.Exec(username, hash) // Inserting new user into the database
			rowsAff, _ := result.RowsAffected()
			lastIns, _ := result.LastInsertId()
			fmt.Println("rowsAff:", rowsAff)
			fmt.Println("lastIns:", lastIns)
			fmt.Println("err:", err)
			if err != nil {
				fmt.Println("error inserting new user")
				return
			}
			session, _ := store.Get(r, "session")                       // Open new session
			session.Values["notice"] = "Your account has been created!" // Store notice to display at "/" root address
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusFound)
		}
	}
	tpl.ExecuteTemplate(w, "register.gohtml", RegErrors)
}

func regValidate(user, pass, pass2 string) bool {
	var rxUsername = regexp.MustCompile("[a-zA-Z0-9._]{8,20}") // RegEx pattern for any alphanumeric, must be between 8 and 20 chars long
	var rxPassword = regexp.MustCompile("[a-zA-Z0-9._]{8,20}") // RegEx pattern for any alphanumeric, must be between 8 and 20 chars long
	matchU := rxUsername.Match([]byte(user))                   // Compares username to RegEx pattern
	matchP := rxPassword.Match([]byte(pass))                   // Compares password to RegEx pattern
	if matchU == false {
		RegErrors = "Please enter a username between 8 and 20 characters long."
	} else if pass != pass2 {
		RegErrors = "Please enter matching passwords."
	} else if matchP == false {
		RegErrors = "Please enter a password between 8 and 20 characters long."
	} else {
		RegErrors = "You've successfully made your account."
		return true
	}
	return false
}

// TODO
// 1. Store if user is logged in
// 2. Logout
