package models

import (
	"time"

	"github.com/jackc/pgx/pgtype"
)

// Represents a Notification sent to a user
type Notification struct {
	id            pgtype.Int4      `db:"id"`
	title         pgtype.Text      `db:"title"`
	content       pgtype.Text      `db:"content"`
	targetUserID  pgtype.Int4      `db:"target_userid"`
	sentTimestamp pgtype.Timestamp `db:"sent_timestamp"`
	seen          pgtype.Bool      `db:"seen"`
}

func (n *Notification) GetId() int {
	return int(n.id.Int)
}

func (n *Notification) GetTitle() string {
	return n.title.String
}

func (n *Notification) GetContent() string {
	return n.content.String
}

func (n *Notification) GetTargetUserID() int {
	return int(n.targetUserID.Int)
}

func (n *Notification) GetSentTimestamp() time.Time {
	return n.sentTimestamp.Time
}

func (n *Notification) GetSeen() bool {
	return n.seen.Bool
}
