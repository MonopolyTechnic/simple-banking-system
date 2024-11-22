package models

import (
	"github.com/jackc/pgx/pgtype"
)

// Represents a checking or savings account
type Account struct {
	AccountNumber       pgtype.Text `db:"account_num"`
	PrimaryCustomerID   pgtype.Int4 `db:"primary_customer_id"`
	SecondaryCustomerID pgtype.Int4 `db:"secondary_customer_id"`
	AccountType         pgtype.Text `db:"account_type"`
	Balance             pgtype.Numeric
	AccountStatus       pgtype.Text
}
