package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

// Wrapper func to read the env file while only returning the map
func readEnv(filepath string) map[string]string {
	env, err := godotenv.Read(filepath)
	handle(err)
	return env
}

// Helper func that acts as a context manager to open a new connection to the database
func OpenDBConnection(fn func(conn *pgxpool.Pool) error) error {
	url := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", env["DB_USERNAME"], env["DB_PASSWORD"], env["DB_HOST"], env["DB_PORT"], env["DB_NAME"])
	conn, err := pgxpool.New(context.Background(), url)
	if err != nil {
		return err
	}
	defer conn.Close()
	return fn(conn)
}

// Helper func to handle errors
func handle(err error, fmtStr ...string) {
	fmt := fmt.Sprintf("%v\n", err)
	if len(fmtStr) >= 1 {
		fmt = fmtStr[0] + ": " + fmt
	}
	if err != nil {
		log.Fatal(fmt)
	}
}