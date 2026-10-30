package results

import (
	"html/template"
	"net/http"

	"github.com/go-chi/render"
	log "github.com/sirupsen/logrus"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/librespeed/speedtest-go/config"
	"github.com/librespeed/speedtest-go/database"
	"github.com/librespeed/speedtest-go/database/schema"
)

type StatsData struct {
	NoPassword bool
	LoggedIn   bool
	Data       []schema.TelemetryData
}

var (
	key   = []byte(securecookie.GenerateRandomKey(32))
	store = sessions.NewCookieStore(key)
	conf  = config.LoadedConfig()
)

func init() {
	store.Options = &sessions.Options{
		Path:     conf.BaseURL + "/stats",
		MaxAge:   3600 * 1, // 1 hour
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

func Stats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, err := template.New("template").Parse(htmlTemplate)
	if err != nil {
		log.Errorf("Failed to parse template: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if conf.DatabaseType == "none" {
		render.PlainText(w, r, "Statistics are disabled")
		return
	}

	var data StatsData

	if conf.StatsPassword == "PASSWORD" {
		data.NoPassword = true
	}

	if !data.NoPassword {
		op := r.FormValue("op")
		session, _ := store.Get(r, "logged")
		auth, ok := session.Values["authenticated"].(bool)

		if auth && ok {
			if op == "logout" {
				session.Values["authenticated"] = false
				session.Options.MaxAge = -1
				session.Save(r, w)
				http.Redirect(w, r, conf.BaseURL+"/stats", http.StatusTemporaryRedirect)
				return
			} else {
				data.LoggedIn = true

				id := r.FormValue("id")
				switch id {
				case "L100":
					stats, err := database.DB.FetchLast100()
					if err != nil {
						log.Errorf("Error fetching data from database: %s", err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					data.Data = stats
				case "":
				default:
					stat, err := database.DB.FetchByUUID(id)
					if err != nil {
						log.Errorf("Error fetching data from database: %s", err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					if stat != nil {
						data.Data = append(data.Data, *stat)
					}
				}
			}
		} else {
			if op == "login" {
				session, _ := store.Get(r, "logged")
				password := r.FormValue("password")
				if password == conf.StatsPassword {
					session.Values["authenticated"] = true
					session.Save(r, w)
					http.Redirect(w, r, conf.BaseURL+"/stats", http.StatusTemporaryRedirect)
					return
				} else {
					w.WriteHeader(http.StatusForbidden)
				}
			}
		}
	}

	if err := t.Execute(w, data); err != nil {
		log.Errorf("Error executing template: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
<link rel="shortcut icon" href="images/favicon.svg" />
<link rel="stylesheet" type="text/css" href="styling/fonts.css?v=2.1" />
<link rel="stylesheet" type="text/css" href="styling/obsidian.css?v=2.1" />
<title>LibreSpeed · Telemetry Vault (Obsidian V2)</title>
<style type="text/css">
	html {
		font-size: 10px;
	}
	body {
		font-family: var(--obs-font-sans);
		font-size: 1.5rem;
		display: flex;
		flex-direction: column;
		min-height: 100vh;
		padding: 0 2.8rem 4rem 2.8rem;
	}
	.obs-stats-shell {
		width: 100%;
		max-width: 118rem;
		margin: 0 auto;
		flex: 1;
	}
	.obs-stats-header-band {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-end;
		justify-content: space-between;
		gap: 1.6rem;
		padding: 2.4rem 0 1.8rem 0;
		border-bottom: 1px solid var(--obs-hairline);
		margin-bottom: 2.4rem;
	}
	h1.obs-stats-title {
		margin: 0;
		font-size: 2.8rem;
		font-weight: 800;
		letter-spacing: -0.08rem;
		color: var(--obs-white);
	}
	p.obs-stats-sub {
		color: var(--obs-slate-400);
		font-size: 1.35rem;
		margin: 0.4rem 0 0 0;
	}
	.obs-auth-panel {
		max-width: 44rem;
		margin: 4.8rem auto;
		padding: 3.2rem 0;
		border-top: 1px solid var(--obs-hairline);
		border-bottom: 1px solid var(--obs-hairline);
		text-align: center;
	}
	.obs-auth-panel h3 {
		font-size: 2.0rem;
		font-weight: 700;
		color: var(--obs-white);
		margin-bottom: 1.4rem;
	}
	.obs-toolbar-strip {
		padding: 0 0 2.0rem 0;
		margin-bottom: 2.4rem;
		border-bottom: 1px solid var(--obs-hairline);
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 1.6rem;
	}
	.obs-search-form {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 1.0rem;
		flex: 1;
	}
	.obs-input {
		background: rgba(15, 23, 42, 0.45);
		border: 1px solid rgba(255, 255, 255, 0.10);
		border-radius: 1.0rem;
		padding: 1.0rem 1.5rem;
		color: var(--obs-white);
		font-family: var(--obs-font-mono);
		font-size: 1.35rem;
		min-width: 24rem;
		outline: none;
		transition: border-color 0.2s, box-shadow 0.2s;
	}
	.obs-input:focus {
		border-color: var(--obs-indigo-400);
		box-shadow: 0 0 18px rgba(99, 102, 241, 0.25);
	}
	.obs-btn-primary {
		background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 55%, #c026d3 100%);
		color: var(--obs-white);
		border: 1px solid rgba(129, 140, 248, 0.40);
		border-radius: 1.0rem;
		padding: 1.0rem 2.0rem;
		font-family: var(--obs-font-sans);
		font-size: 1.3rem;
		font-weight: 700;
		cursor: pointer;
		box-shadow: 0 6px 20px rgba(99, 102, 241, 0.25);
		transition: transform 0.16s, box-shadow 0.16s;
	}
	.obs-btn-primary:hover {
		transform: translateY(-1px);
		box-shadow: 0 10px 26px rgba(168, 85, 247, 0.35);
	}
	.obs-btn-secondary {
		background: rgba(255, 255, 255, 0.04);
		color: var(--obs-slate-200);
		border: 1px solid rgba(255, 255, 255, 0.10);
		border-radius: 1.0rem;
		padding: 1.0rem 1.8rem;
		font-family: var(--obs-font-sans);
		font-size: 1.3rem;
		font-weight: 600;
		cursor: pointer;
		transition: background 0.16s, color 0.16s;
	}
	.obs-btn-secondary:hover {
		background: rgba(255, 255, 255, 0.09);
		color: var(--obs-white);
	}
	.obs-record-block {
		padding: 1.8rem 0;
		border-bottom: 1px solid var(--obs-hairline);
		overflow-x: auto;
	}
	table.obs-table {
		width: 100%;
		border-collapse: collapse;
	}
	table.obs-table tr {
		border-bottom: 1px solid rgba(148, 163, 184, 0.08);
	}
	table.obs-table tr:last-child {
		border-bottom: none;
	}
	table.obs-table th {
		width: 18rem;
		text-align: left;
		padding: 0.85rem 1.2rem 0.85rem 0;
		font-size: 1.15rem;
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.08em;
		color: var(--obs-slate-400);
		vertical-align: top;
	}
	table.obs-table td {
		padding: 0.85rem 1.2rem;
		font-family: var(--obs-font-mono);
		font-size: 1.35rem;
		color: var(--obs-slate-200);
		word-break: break-all;
	}
</style>
</head>
<body>
<header class="obs-header">
	<div class="obs-header-left">
		<a class="obs-brand" href="./">
			<img src="images/logo.svg" alt="LibreSpeed" />
			<span class="obs-brand-divider" aria-hidden="true"></span>
			<span class="obs-badge">
				<span class="obs-beacon-live"></span>
				Obsidian V2
			</span>
		</a>
		<span class="obs-header-subtitle">High-BDP Multi-Stream Network Telemetry</span>
	</div>
	<nav class="obs-nav-pills" aria-label="Telemetry View Switcher">
		<a class="obs-tab-pill" href="./">Speedtest Stage</a>
		<a class="obs-tab-pill obs-tab-pill-active" href="stats">Telemetry Vault</a>
	</nav>
</header>

<div class="obs-stats-shell">
	<div class="obs-stats-header-band">
		<div>
			<h1 class="obs-stats-title">Telemetry Statistics Vault</h1>
			<p class="obs-stats-sub">Recorded BoltDB Throughput &amp; Latency Benchmarks</p>
		</div>
	</div>

	{{ if .NoPassword }}
	<div class="obs-auth-panel">
		<h3>Telemetry Vault Locked</h3>
		<p style="color:var(--obs-slate-400);">Please set <code>statistics_password</code> in <code>settings.toml</code> to enable access.</p>
	</div>
	{{ else if .LoggedIn }}
	<div class="obs-toolbar-strip">
		<form class="obs-search-form" action="stats" method="GET">
			<input type="hidden" name="op" value="id" />
			<input class="obs-input" type="text" name="id" id="id" placeholder="Enter Test ULID..." value="" />
			<input class="obs-btn-primary" type="submit" value="Lookup Test" />
			<input class="obs-btn-secondary" type="submit" onclick="document.getElementById('id').value='L100'" value="Load Last 100 Tests" />
		</form>
		<form action="stats" method="GET">
			<input type="hidden" name="op" value="logout" />
			<input class="obs-btn-secondary" type="submit" value="Sign Out" />
		</form>
	</div>

	{{ range $i, $v := .Data }}
	<div class="obs-record-block">
		<table class="obs-table">
			<tr><th>Test ID</th><td style="color:var(--obs-sky-400);font-weight:700;">{{ $v.UUID }}</td></tr>
			<tr><th>Timestamp</th><td>{{ $v.Timestamp }}</td></tr>
			<tr><th>Client IP &amp; ISP</th><td>{{ $v.IPAddress }}<br/><span style="color:var(--obs-slate-400);">{{ $v.ISPInfo }}</span></td></tr>
			<tr><th>User Agent</th><td>{{ $v.UserAgent }} ({{ $v.Language }})</td></tr>
			<tr><th>Download</th><td style="color:var(--obs-fuchsia-400);font-weight:700;">{{ $v.Download }} Mbps</td></tr>
			<tr><th>Upload</th><td style="color:var(--obs-sky-400);font-weight:700;">{{ $v.Upload }} Mbps</td></tr>
			<tr><th>Ping</th><td style="color:var(--obs-emerald-400);font-weight:700;">{{ $v.Ping }} ms</td></tr>
			<tr><th>Jitter</th><td style="color:var(--obs-indigo-300);font-weight:700;">{{ $v.Jitter }} ms</td></tr>
			<tr><th>Telemetry Log</th><td>{{ $v.Log }}</td></tr>
			<tr><th>Extra Metadata</th><td>{{ $v.Extra }}</td></tr>
		</table>
	</div>
	{{ end }}
	{{ else }}
	<div class="obs-auth-panel">
		<h3>Operator Authentication</h3>
		<form action="stats?op=login" method="POST" style="display:flex;flex-direction:column;gap:1.4rem;align-items:center;">
			<input class="obs-input" style="width:100%;" type="password" name="password" placeholder="Operator Password" value="" />
			<input class="obs-btn-primary" style="width:100%;" type="submit" value="Unlock Telemetry Vault" />
		</form>
	</div>
	{{ end }}
</div>
</body>
</html>`
