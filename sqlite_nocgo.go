//go:build !cgo

package main

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

func openSQLiteDB(dsn string) (*sql.DB, error) {
	return sql.Open("sqlite", dsn)
}
