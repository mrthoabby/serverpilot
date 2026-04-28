package dbquery

// Blank-import the supported database drivers so they register
// themselves with database/sql. Adding a driver here is a security
// decision because it expands the protocol surface of the dashboard;
// keep this list minimal and aligned with Engine.DriverName().
import (
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)
