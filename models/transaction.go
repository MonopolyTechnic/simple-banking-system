package models

import (
	"time"

	"github.com/jackc/pgx/pgtype"
)

// Represents a Transaction and its data
type Transaction struct {
	id              pgtype.Int8 `db:"transaction_id"`
	sourceId        pgtype.Text `db:"source_account"`
	recipientId     pgtype.Text `db:"recipient_account"`
	amount          pgtype.Numeric
	transactionType pgtype.Text      `db:"transaction_type"`
	timestamp       pgtype.Timestamp `db:"transaction_timestamp"`
}

func (t *Transaction) GetId() int64 {
	return t.id.Int
}

func (t *Transaction) GetSourceId() string {
	return t.sourceId.String
}

func (t *Transaction) GetRecipientId() string {
	return t.recipientId.String
}

func (t *Transaction) GetAmount() pgtype.Numeric {
	return t.amount
}

func (t *Transaction) GetType() string {
	return t.transactionType.String
}

func (t *Transaction) GetTimestamp() time.Time {
	return t.timestamp.Time
}
