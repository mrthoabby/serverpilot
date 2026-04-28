package dbquery

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"
)

// SchemaTree is the database-level layout the dashboard renders as a
// browseable list: schemas → tables → columns. PK columns are flagged
// inline so the UI can mark them.
type SchemaTree struct {
	Schemas []SchemaNode `json:"schemas"`
}

type SchemaNode struct {
	Name   string      `json:"name"`
	Tables []TableNode `json:"tables"`
}

type TableNode struct {
	Name       string       `json:"name"`
	Kind       string       `json:"kind"` // "table" | "view" | "matview" | "partitioned" | "foreign"
	Columns    []ColumnNode `json:"columns"`
	PrimaryKey []string     `json:"primary_key,omitempty"`
}

type ColumnNode struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	Default  string `json:"default,omitempty"`
	IsPK     bool   `json:"is_pk,omitempty"`
}

// LoadSchema enumerates schemas / tables / columns / PKs for the
// connection identified by `id`. Postgres only. Skips system schemas.
//
// Three short queries, joined client-side. The assembled tree is the
// closest match to "what an admin tool like pgAdmin would show". The
// dashboard never sends arbitrary SQL on behalf of the operator here —
// the queries are static, parameterised by nothing, and only read from
// pg_catalog and information_schema.
func (s *Service) LoadSchema(id, sessionSecret string) (*SchemaTree, error) {
	engine, dsn, _, err := s.resolveDSN(id, sessionSecret)
	if err != nil {
		return nil, err
	}
	if engine != EnginePostgres {
		return nil, errors.New("schema browsing is only supported on postgres connections in this version")
	}

	db, err := sql.Open(engine.DriverName(), dsn)
	if err != nil {
		return nil, sanitizeDriverError(err)
	}
	defer db.Close()
	db.SetConnMaxLifetime(QueryTimeout)
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1) Tables (and views, materialized views, foreign tables, partitioned).
	tablesQ := `
		select n.nspname, c.relname, c.relkind
		from pg_class c
		join pg_namespace n on n.oid = c.relnamespace
		where c.relkind in ('r','p','v','m','f')
		  and n.nspname not in ('pg_catalog','information_schema','pg_toast')
		  and n.nspname not like 'pg_temp_%'
		  and n.nspname not like 'pg_toast_temp_%'
		order by n.nspname, c.relname
	`
	type tablerow struct{ schema, table, kind string }
	rows, err := db.QueryContext(ctx, tablesQ)
	if err != nil {
		return nil, sanitizeDriverError(err)
	}
	var tables []tablerow
	for rows.Next() {
		var r tablerow
		var k string
		if err := rows.Scan(&r.schema, &r.table, &k); err != nil {
			rows.Close()
			return nil, err
		}
		switch k {
		case "r":
			r.kind = "table"
		case "p":
			r.kind = "partitioned"
		case "v":
			r.kind = "view"
		case "m":
			r.kind = "matview"
		case "f":
			r.kind = "foreign"
		default:
			r.kind = "table"
		}
		tables = append(tables, r)
	}
	rows.Close()

	// 2) Columns for every relation in scope.
	columnsQ := `
		select n.nspname, c.relname, a.attname,
		       pg_catalog.format_type(a.atttypid, a.atttypmod) as data_type,
		       not a.attnotnull as nullable,
		       coalesce(pg_get_expr(d.adbin, d.adrelid), '') as default_expr,
		       a.attnum
		from pg_attribute a
		join pg_class c on c.oid = a.attrelid
		join pg_namespace n on n.oid = c.relnamespace
		left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum
		where a.attnum > 0 and not a.attisdropped
		  and c.relkind in ('r','p','v','m','f')
		  and n.nspname not in ('pg_catalog','information_schema','pg_toast')
		  and n.nspname not like 'pg_temp_%'
		order by n.nspname, c.relname, a.attnum
	`
	type colrow struct {
		schema, table, name, dtype, def string
		nullable                        bool
	}
	colsByTable := map[string][]colrow{}
	rows, err = db.QueryContext(ctx, columnsQ)
	if err != nil {
		return nil, sanitizeDriverError(err)
	}
	for rows.Next() {
		var r colrow
		var attnum int
		if err := rows.Scan(&r.schema, &r.table, &r.name, &r.dtype, &r.nullable, &r.def, &attnum); err != nil {
			rows.Close()
			return nil, err
		}
		key := r.schema + "." + r.table
		colsByTable[key] = append(colsByTable[key], r)
	}
	rows.Close()

	// 3) Primary keys.
	pkQ := `
		select n.nspname, c.relname, a.attname
		from pg_index i
		join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any(i.indkey)
		join pg_class c on c.oid = i.indrelid
		join pg_namespace n on n.oid = c.relnamespace
		where i.indisprimary
		  and n.nspname not in ('pg_catalog','information_schema','pg_toast')
		order by n.nspname, c.relname, array_position(i.indkey, a.attnum)
	`
	pksByTable := map[string][]string{}
	rows, err = db.QueryContext(ctx, pkQ)
	if err == nil {
		for rows.Next() {
			var schema, table, col string
			if err := rows.Scan(&schema, &table, &col); err != nil {
				rows.Close()
				return nil, err
			}
			pksByTable[schema+"."+table] = append(pksByTable[schema+"."+table], col)
		}
		rows.Close()
	}

	// Assemble tree.
	bySchema := map[string]*SchemaNode{}
	for _, t := range tables {
		key := t.schema + "." + t.table
		pkSet := map[string]bool{}
		for _, c := range pksByTable[key] {
			pkSet[c] = true
		}
		var cols []ColumnNode
		for _, c := range colsByTable[key] {
			cols = append(cols, ColumnNode{
				Name:     c.name,
				Type:     c.dtype,
				Nullable: c.nullable,
				Default:  c.def,
				IsPK:     pkSet[c.name],
			})
		}
		tn := TableNode{
			Name:       t.table,
			Kind:       t.kind,
			Columns:    cols,
			PrimaryKey: pksByTable[key],
		}
		sn, ok := bySchema[t.schema]
		if !ok {
			sn = &SchemaNode{Name: t.schema}
			bySchema[t.schema] = sn
		}
		sn.Tables = append(sn.Tables, tn)
	}
	out := &SchemaTree{}
	keys := make([]string, 0, len(bySchema))
	for k := range bySchema {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Schemas = append(out.Schemas, *bySchema[k])
	}
	return out, nil
}
