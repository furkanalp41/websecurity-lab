// SPDX-License-Identifier: MIT
//
// Groove Depot — a tiny promotional microsite with a deliberately vulnerable
// analytics cookie (CWE-89, OWASP A03:2021).
//
// On first visit the app assigns a random `TrackingId` cookie. On every request
// it looks up the personalised banner for that cookie by concatenating the raw
// cookie value straight into a SQL string:
//
//	SELECT banner FROM banners WHERE trackingid = '<cookie>'
//
// Because the injection sink is the Cookie header rather than a query-string
// parameter, learners who only fuzz the URL miss it entirely. A one-column
// UNION lets an attacker read internal_config.license_key, which unlocks the
// gated /solve endpoint that returns the per-container flag.
//
// SQLite runs in-process (mattn/go-sqlite3), so this is a single container with
// no separate database service and no reverse proxy.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"html"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/mattn/go-sqlite3"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// randHex returns 2*n lowercase hex characters from a CSPRNG.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is unrecoverable for this program.
		log.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

// initDB opens the on-tmpfs SQLite database, creates the schema, seeds the
// banner rows, and installs a random per-container license_key. It returns the
// live *sql.DB and the license_key so /solve can compare against it without a
// second query path.
func initDB(path string) (*sql.DB, string, error) {
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000")
	if err != nil {
		return nil, "", err
	}
	// A single connection keeps the in-process store simple and lock-free; this
	// is a low-traffic teaching lab, not a production workload.
	db.SetMaxOpenConns(1)

	const schema = `
CREATE TABLE IF NOT EXISTS banners (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  trackingid TEXT NOT NULL,
  banner     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS internal_config (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  config_key  TEXT NOT NULL,
  license_key TEXT NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		return nil, "", err
	}

	var banners int
	if err := db.QueryRow("SELECT count(*) FROM banners").Scan(&banners); err != nil {
		return nil, "", err
	}
	if banners == 0 {
		_, err := db.Exec(`INSERT INTO banners (trackingid, banner) VALUES
			('promo-spring',     'Spring sale: 20% off all reissues this week.'),
			('promo-newsletter', 'Join the crate-diggers newsletter for early drops.'),
			('promo-default',    'Welcome to Groove Depot.')`)
		if err != nil {
			return nil, "", err
		}
	}

	// The license_key is random per container and never derived from the flag
	// secret; the flag itself is written by entrypoint.sh outside the app.
	license := "LK_" + randHex(20)
	var cfg int
	if err := db.QueryRow("SELECT count(*) FROM internal_config").Scan(&cfg); err != nil {
		return nil, "", err
	}
	if cfg == 0 {
		if _, err := db.Exec(
			"INSERT INTO internal_config (config_key, license_key) VALUES (?, ?)",
			"site_license", license,
		); err != nil {
			return nil, "", err
		}
	} else if err := db.QueryRow(
		"SELECT license_key FROM internal_config ORDER BY id LIMIT 1",
	).Scan(&license); err != nil {
		return nil, "", err
	}
	return db, license, nil
}

// lookupBanners runs the vulnerable personalisation query.
//
// VULNERABILITY (CWE-89): the tracking-id value is concatenated raw into the SQL
// text with no parameterisation, quoting, or allowlist. A parameter placeholder
// (`?`) here would close the hole entirely.
func lookupBanners(db *sql.DB, trackingID string) ([]string, error) {
	query := "SELECT banner FROM banners WHERE trackingid = '" + trackingID + "'"
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func homeHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var trackingID string
		if c, err := r.Cookie("TrackingId"); err == nil && c.Value != "" {
			trackingID = c.Value
		} else {
			trackingID = randHex(16)
			http.SetCookie(w, &http.Cookie{
				Name:     "TrackingId",
				Value:    trackingID,
				Path:     "/",
				Expires:  time.Now().Add(24 * time.Hour),
				SameSite: http.SameSiteLaxMode,
			})
		}

		banners, qErr := lookupBanners(db, trackingID)

		var b strings.Builder
		b.WriteString("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">")
		b.WriteString("<title>Groove Depot</title></head><body>\n")
		b.WriteString("<h1>Groove Depot</h1>\n")
		b.WriteString("<p>Your tracking id: <code>" + html.EscapeString(trackingID) + "</code></p>\n")
		switch {
		case qErr != nil:
			// Verbose personalisation error (a realistic misconfiguration). Not
			// the intended channel — the UNION result renders inline below.
			b.WriteString("<p>Personalisation unavailable: " + html.EscapeString(qErr.Error()) + "</p>\n")
		case len(banners) == 0:
			b.WriteString("<p>No personalised banner for your tracking id yet.</p>\n")
		default:
			b.WriteString("<div id=\"banner\">\n")
			for _, bn := range banners {
				b.WriteString("<p class=\"promo\">" + html.EscapeString(bn) + "</p>\n")
			}
			b.WriteString("</div>\n")
		}
		b.WriteString("</body></html>\n")

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	}
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

// solveHandler releases the flag only when the caller proves knowledge of the
// per-container license_key — which is only recoverable through the injection.
func solveHandler(license, flagPath string) http.HandlerFunc {
	want := []byte(license)
	return func(w http.ResponseWriter, r *http.Request) {
		guess := []byte(r.URL.Query().Get("license"))
		if len(guess) > 0 && subtle.ConstantTimeCompare(guess, want) == 1 {
			data, err := os.ReadFile(flagPath)
			if err != nil {
				http.Error(w, "flag unavailable", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusPaymentRequired) // 402
		_, _ = w.Write([]byte("Invalid or missing license key.\n"))
	}
}

func main() {
	dbPath := getenv("DB_PATH", "/tmp/lab.sqlite")
	flagPath := getenv("FLAG_PATH", "/var/lib/lab/flag.txt")
	listen := getenv("LISTEN", ":8080")

	db, license, err := initDB(dbPath)
	if err != nil {
		log.Fatalf("init db: %v", err)
	}

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Get("/", homeHandler(db))
	r.Get("/health", healthHandler)
	r.Get("/solve", solveHandler(license, flagPath))

	srv := &http.Server{
		Addr:              listen,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("groove-depot listening on %s", listen)
	log.Fatal(srv.ListenAndServe())
}
