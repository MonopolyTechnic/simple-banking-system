package models

import (
	"math"

	"github.com/jackc/pgx/pgtype"
)

// Represents a checking or savings account
type Account struct {
	accountNumber       pgtype.Varchar `db:"account_num"`
	primaryCustomerID   pgtype.Int4    `db:"primary_customer_id"`
	secondaryCustomerID pgtype.Int4    `db:"secondary_customer_id"`
	accountType         pgtype.Varchar `db:"account_type"`
	balance             pgtype.Numeric
	accountStatus       pgtype.Varchar
}

func (a *Account) GetAccountNumber() string {
	return a.accountNumber.String
}

func (a *Account) GetPrimaryCustomerID() int {
	return int(a.primaryCustomerID.Int)
}

func (a *Account) HasSecondaryCustomerID() bool {
	return a.secondaryCustomerID.Status == pgtype.Present
}

func (a *Account) GetSecondaryCustomerID() int {
	return int(a.secondaryCustomerID.Int)
}

func (a *Account) GetAccountType() string {
	return a.accountType.String
}

func (a *Account) GetBalance() float64 {
	return float64(a.balance.Int.Int64()) * math.Pow(10, float64(a.balance.Exp))
}

func (a *Account) GetAccountStatus() string {
	return a.accountStatus.String
}
