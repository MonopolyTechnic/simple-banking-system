package models

import (
	"github.com/jackc/pgx/pgtype"
)

// Represents a Notification sent to a user
type Notification struct {
	Id            int              `db:"id"`
	Title         pgtype.Text      `db:"title"`
	Content       pgtype.Text      `db:"content"`
	TargetUserID  pgtype.Int4      `db:"target_userid"`
	SentTimestamp pgtype.Timestamp `db:"sent_timestamp"`
	Seen          pgtype.Bool      `db:"seen"`
}
