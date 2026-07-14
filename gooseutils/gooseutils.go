package gooseutils

import (
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
)

func RunMigrations(db *sql.DB, fs embed.FS) error {
	fmt.Println("running goose migrations")
	goose.SetDialect("postgres")
	goose.SetBaseFS(fs)

	if err := goose.Up(db, "schema"); err != nil {
		return err
	}
	if err := goose.Version(db, "schema"); err != nil {
		return err
	}
	fmt.Println("goose migrations successful")
	return nil
}
