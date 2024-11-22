package models

import (
	"github.com/jackc/pgx/pgtype"
)

// Represents a Profile (online account) and its data
type Profile struct {
	Id             int
	ProfileType    pgtype.Text `db:"profile_type"`
	FirstName      pgtype.Text `db:"first_name"`
	MiddleName     pgtype.Text `db:"middle_name"`
	LastName       pgtype.Text `db:"last_name"`
	Email          pgtype.Text
	DateOfBirth    pgtype.Date  `db:"date_of_birth"`
	BillingAddress pgtype.Text  `db:"billing_address"`
	PhoneNumber    pgtype.Text  `db:"phone_number"`
	PhoneCarrier   pgtype.Text  `db:"phone_carrier"`
	PasswordHash   pgtype.Bytea `db:"password_hash"`
	MaskedPassword pgtype.Text  `db:"masked_password"`
}
