package main

import (
	"database/sql"
	"log"
	"net/http"

	"../REST-API-AWT-AUTH-WITH-GOLANG/controllers"
	driver "../REST-API-AWT-AUTH-WITH-GOLANG/driver"

	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
)

func init() {
	gotenv.Load()
}

var db *sql.DB

func main() {
	db = driver.ConnectDB()

	controller := controllers.Controller{}
	router := mux.NewRouter()

	router.HandleFunc("/signup", controller.SignUp(db)).Methods("POST")
	router.HandleFunc("/login", controller.Login(db)).Methods("POST")
	router.HandleFunc("/protected", controller.TokenVerifyMiddleWare(controller.ProtectedEndPoint())).Methods("GET")

	log.Println("Listen on port 8000....")
	log.Fatal(http.ListenAndServe(":8000", router))
}
