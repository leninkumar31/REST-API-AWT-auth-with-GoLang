package driver

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/lib/pq"
)

var db *sql.DB

func ConnectDB() *sql.DB {
	pgURL, err := pq.ParseURL(os.Getenv("ELEPHANTSQL_URL"))

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(pgURL)

	db, err = sql.Open("postgres", pgURL)
	if err != nil {
		log.Fatal(err)
	}
	//err = db.Ping()
	return db
}
