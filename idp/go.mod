module github.com/aikazzh/portfolio/idp

go 1.26

require (
	github.com/aikazzh/portfolio/keysmith v0.0.0
	golang.org/x/crypto v0.39.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.10.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)

replace github.com/aikazzh/portfolio/keysmith => ../keysmith
