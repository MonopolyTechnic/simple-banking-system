package models

import (
	"math"
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

func (t *Transaction) HasSourceId() bool {
	return t.sourceId.Status == pgtype.Present
}

func (t *Transaction) HasRecipientId() bool {
	return t.recipientId.Status == pgtype.Present
}

func (t *Transaction) GetSourceId() string {
	return t.sourceId.String
}

func (t *Transaction) GetRecipientId() string {
	return t.recipientId.String
}

func (t *Transaction) GetAmount() float64 {
	return float64(t.amount.Int.Int64()) * math.Pow(10, float64(t.amount.Exp))
}

func (t *Transaction) GetType() string {
	return t.transactionType.String
}

func (t *Transaction) GetTimestamp() time.Time {
	return t.timestamp.Time
}
