package models

import (
	"github.com/jackc/pgx/pgtype"
)

// Represents a Transaction and its data
type Transaction struct {
	Id          int64       `db:"transaction_id"`
	SourceId    pgtype.Text `db:"source_account"`
	RecipientId pgtype.Text `db:"recipient_account"`
	Amount      pgtype.Numeric
	Type        pgtype.Text      `db:"transaction_type"`
	Timestamp   pgtype.Timestamp `db:"transaction_timestamp"`
}
