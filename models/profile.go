package models

import (
	"time"

	"github.com/jackc/pgx/pgtype"
)

// Represents a Profile (online account) and its data
type Profile struct {
	id             pgtype.Int4
	profileType    pgtype.Text `db:"profile_type"`
	firstName      pgtype.Text `db:"first_name"`
	middleName     pgtype.Text `db:"middle_name"`
	lastName       pgtype.Text `db:"last_name"`
	email          pgtype.Text
	dateOfBirth    pgtype.Date  `db:"date_of_birth"`
	billingAddress pgtype.Text  `db:"billing_address"`
	phoneNumber    pgtype.Text  `db:"phone_number"`
	phoneCarrier   pgtype.Text  `db:"phone_carrier"`
	passwordHash   pgtype.Bytea `db:"password_hash"`
	maskedPassword pgtype.Text  `db:"masked_password"`
}

func (p *Profile) GetId() int {
	return int(p.id.Int)
}

func (p *Profile) GetProfileType() string {
	return p.profileType.String
}

func (p *Profile) GetFirstName() string {
	return p.firstName.String
}

func (p *Profile) GetMiddleName() string {
	return p.middleName.String
}

func (p *Profile) GetLastName() string {
	return p.lastName.String
}

func (p *Profile) GetEmail() string {
	return p.email.String
}

func (p *Profile) GetDateOfBirth() time.Time {
	return p.dateOfBirth.Time
}

func (p *Profile) GetBillingAddress() string {
	return p.billingAddress.String
}

func (p *Profile) GetPhoneNumber() string {
	return p.phoneNumber.String
}

func (p *Profile) GetPhoneCarrier() string {
	return p.phoneCarrier.String
}

func (p *Profile) GetPasswordHash() []byte {
	return p.passwordHash.Bytes
}

func (p *Profile) GetMaskedPassword() string {
	return p.maskedPassword.String
}
