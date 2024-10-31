package models

import "time"

type Employee struct {
	Id             int
	FirstName      string
	MiddleName     string
	LastName       string
	Email          string
	DOB            time.Time
	BillingAddress string
	PhoneNum       string
	PasswordHash   []byte
}
