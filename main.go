package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

var db *sql.DB

func main() {
	pgURL, err := pq.ParseURL("postgres://xgpcduws:4l7tyIBUSqErzDBSJUN83CgxWQS1jH7e@john.db.elephantsql.com:5432/xgpcduws")

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(pgURL)

	db, err = sql.Open("postgres", pgURL)
	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping()

	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndPoint)).Methods("GET")

	log.Println("Listen on port 8000....")
	log.Fatal(http.ListenAndServe(":8000", router))
}

func respondWithError(w http.ResponseWriter, status int, err Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(err)
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var err Error
	json.NewDecoder(r.Body).Decode(&user)
	if user.Email == "" {
		err.Message = "Email is missing"
		respondWithError(w, http.StatusBadRequest, err)
		return
	}

	if user.Password == "" {
		err.Message = "Password is missing"
		respondWithError(w, http.StatusBadRequest, err)
		return
	}

	hash, error := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if error != nil {
		log.Fatal(error)
	}
	user.Password = string(hash)
	stmt := "insert into users (email,password) values($1,$2) RETURNING id;"
	error = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)
	if error != nil {
		err.Message = "Server Error!"
		respondWithError(w, http.StatusInternalServerError, err)
		return
	}
	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)
}

func login(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Successfully called login"))
}

func protectedEndPoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndpoint invoked.")
}

func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	fmt.Println("TokenVerifyMiddleware invoked.")
	return nil
}
