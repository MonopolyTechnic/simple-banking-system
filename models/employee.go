package models

import (
	"github.com/jackc/pgx/pgtype"
)

type Employee struct {
	Id             int
	FirstName      pgtype.Text `db:"first_name"`
	MiddleName     pgtype.Text `db:"middle_name"`
	LastName       pgtype.Text `db:"last_name"`
	Email          pgtype.Text
	DateOfBirth    pgtype.Date  `db:"date_of_birth"`
	BillingAddress pgtype.Text  `db:"billing_address"`
	PhoneNumber    pgtype.Text  `db:"phone_number"`
	PasswordHash   pgtype.Bytea `db:"password_hash"`
}