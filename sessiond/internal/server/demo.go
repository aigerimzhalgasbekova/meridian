package server

// The demo is a minimal browser flow over the same store the API uses:
// login → session cookie → protected page → rotate / logout / logout
// everywhere. It exists to make the distributed-session behavior visible
// (open two browsers, log out everywhere in one, watch the other die).
//
// It is dependency-free server-rendered HTML in the idp house style: inline
// styles, no JavaScript. CSRF on the POST actions relies on SameSite=Lax
// cookies. ponytail: fine for a demo surface; add double-submit tokens if
// this ever fronted real users.

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"html/template"
	"net/http"
	"time"

	"github.com/aikazzh/portfolio/sessiond/internal/store"
)

func subtleEqual(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

const (
	demoRealm  = "demo"
	demoCookie = "meridian_session"
)

// demoUsers are fixed demo credentials, shown on the login page.
var demoUsers = map[string]string{
	"alice": "wonderland",
	"bob":   "builder",
}

var demoPage = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · sessiond demo</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; display: grid; place-items: center;
         min-height: 100vh; margin: 0; background: light-dark(#f4f4f5, #18181b);
         color: light-dark(#18181b, #f4f4f5); }
  .card { background: light-dark(#fff, #27272a); border-radius: 12px; padding: 2rem;
          width: min(34rem, 92vw); box-shadow: 0 4px 24px rgba(0,0,0,.08); }
  h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
  p.sub { margin: 0 0 1.5rem; color: light-dark(#52525b, #a1a1aa); font-size: .875rem; }
  label { display: block; font-size: .8125rem; font-weight: 600; margin: 1rem 0 .25rem; }
  input { width: 100%; box-sizing: border-box; padding: .5rem .75rem; font-size: 1rem;
    border: 1px solid light-dark(#d4d4d8, #3f3f46); border-radius: 8px;
    background: transparent; color: inherit; }
  button { padding: .625rem 1rem; border: 0; border-radius: 8px; background: #4f46e5;
    color: #fff; font-size: .9375rem; font-weight: 600; cursor: pointer; margin-top: .75rem; }
  button.secondary { background: transparent; color: light-dark(#52525b, #a1a1aa);
    border: 1px solid light-dark(#d4d4d8, #3f3f46); }
  button.danger { background: #b91c1c; }
  form.inline { display: inline-block; margin-right: .5rem; }
  .error { background: light-dark(#fef2f2, #3f1d1d); color: light-dark(#b91c1c, #fca5a5);
    border-radius: 8px; padding: .625rem .75rem; font-size: .875rem; margin-bottom: 1rem; }
  table { width: 100%; border-collapse: collapse; font-size: .8125rem; margin: 1rem 0; }
  th, td { text-align: left; padding: .375rem .5rem; border-bottom: 1px solid light-dark(#e4e4e7, #3f3f46); }
  code { font: .8125rem ui-monospace, monospace; }
  .badge { font-size: .6875rem; font-weight: 700; color: #4f46e5; }
</style>
</head>
<body><div class="card">{{template "body" .}}</div></body>
</html>`))

var demoLoginTmpl = template.Must(template.Must(demoPage.Clone()).Parse(`{{define "body"}}
<h1>Sign in</h1>
<p class="sub">sessiond demo — try alice/wonderland or bob/builder</p>
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
<form method="post" action="/demo/login">
  <label for="username">Username</label>
  <input type="text" id="username" name="username" autocomplete="username" autofocus required>
  <label for="password">Password</label>
  <input type="password" id="password" name="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
</form>
{{end}}`))

var demoHomeTmpl = template.Must(template.Must(demoPage.Clone()).Parse(`{{define "body"}}
<h1>Hello, {{.User}}</h1>
<p class="sub">This page requires a live session. Session ID <code>{{.Short}}…</code>,
created {{.Created}}, expires no later than {{.Deadline}}.</p>
<table>
<tr><th>Session</th><th>Created</th><th>Last seen</th><th>IP</th><th></th></tr>
{{range .Sessions}}
<tr>
  <td><code>{{printf "%.12s" .ID}}…</code>{{if .Current}} <span class="badge">THIS</span>{{end}}</td>
  <td>{{.CreatedAt.Format "15:04:05"}}</td>
  <td>{{.LastSeenAt.Format "15:04:05"}}</td>
  <td>{{.IP}}</td>
  <td></td>
</tr>
{{end}}
</table>
<form class="inline" method="post" action="/demo/rotate"><button class="secondary">Rotate session (elevate)</button></form>
<form class="inline" method="post" action="/demo/logout"><button class="secondary">Log out</button></form>
<form class="inline" method="post" action="/demo/logout-all"><button class="danger">Log out everywhere</button></form>
{{end}}`))

func (s *Server) mountDemo(mux *http.ServeMux) {
	mux.HandleFunc("GET /demo/{$}", s.demoHome)
	mux.HandleFunc("GET /demo/login", s.demoLoginPage)
	mux.HandleFunc("POST /demo/login", s.demoLogin)
	mux.HandleFunc("POST /demo/logout", s.demoLogout)
	mux.HandleFunc("POST /demo/logout-all", s.demoLogoutAll)
	mux.HandleFunc("POST /demo/rotate", s.demoRotate)
}

func setDemoCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: demoCookie, Value: token, Path: "/demo",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

// demoSession resolves the cookie to a live session, or redirects to login.
func (s *Server) demoSession(w http.ResponseWriter, r *http.Request) (string, store.Session, bool) {
	c, err := r.Cookie(demoCookie)
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/demo/login", http.StatusSeeOther)
		return "", store.Session{}, false
	}
	sess, err := s.store.Validate(r.Context(), c.Value)
	if err != nil {
		setDemoCookie(w, "", -1)
		http.Redirect(w, r, "/demo/login", http.StatusSeeOther)
		return "", store.Session{}, false
	}
	return c.Value, sess, true
}

func (s *Server) demoLoginPage(w http.ResponseWriter, r *http.Request) {
	s.renderDemo(w, demoLoginTmpl, map[string]any{"Title": "Sign in"})
}

func (s *Server) demoLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	user, pass := r.PostFormValue("username"), r.PostFormValue("password")
	// Constant-time comparison against the stored password; a decoy check
	// keeps unknown-user timing in the same ballpark. Demo-grade auth: real
	// deployments authenticate in idp, sessiond only manages sessions.
	want, known := demoUsers[user]
	if !known {
		want = "decoy-password-for-timing"
	}
	if !subtleEqual(pass, want) || !known {
		s.renderDemo(w, demoLoginTmpl, map[string]any{"Title": "Sign in", "Error": "Invalid username or password."})
		return
	}

	// Session fixation defense: any pre-login session is revoked, and the
	// cookie is always a freshly minted post-authentication session.
	if c, err := r.Cookie(demoCookie); err == nil && c.Value != "" {
		_ = s.store.RevokeToken(r.Context(), c.Value)
	}
	token, _, err := s.store.Create(r.Context(), demoRealm, user, clientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, store.ErrSessionLimit) {
			s.renderDemo(w, demoLoginTmpl, map[string]any{"Title": "Sign in", "Error": "Too many active sessions."})
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setDemoCookie(w, token, 0)
	http.Redirect(w, r, "/demo/", http.StatusSeeOther)
}

func (s *Server) demoHome(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := s.demoSession(w, r)
	if !ok {
		return
	}
	all, err := s.store.List(r.Context(), demoRealm, sess.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	type row struct {
		store.Session
		Current bool
	}
	rows := make([]row, len(all))
	for i, x := range all {
		rows[i] = row{Session: x, Current: x.ID == sess.ID}
	}
	s.renderDemo(w, demoHomeTmpl, map[string]any{
		"Title": "Protected", "User": sess.UserID, "Short": sess.ID[:12],
		"Created":  sess.CreatedAt.Format(time.TimeOnly),
		"Deadline": sess.AbsDeadline.Format(time.TimeOnly),
		"Sessions": rows,
	})
}

func (s *Server) demoRotate(w http.ResponseWriter, r *http.Request) {
	token, _, ok := s.demoSession(w, r)
	if !ok {
		return
	}
	newToken, _, err := s.store.Rotate(r.Context(), token, clientIP(r), r.UserAgent())
	if err != nil {
		setDemoCookie(w, "", -1)
		http.Redirect(w, r, "/demo/login", http.StatusSeeOther)
		return
	}
	setDemoCookie(w, newToken, 0)
	http.Redirect(w, r, "/demo/", http.StatusSeeOther)
}

func (s *Server) demoLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(demoCookie); err == nil && c.Value != "" {
		_ = s.store.RevokeToken(r.Context(), c.Value)
	}
	setDemoCookie(w, "", -1)
	http.Redirect(w, r, "/demo/login", http.StatusSeeOther)
}

func (s *Server) demoLogoutAll(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := s.demoSession(w, r)
	if !ok {
		return // demoSession already redirected
	}
	if _, err := s.store.RevokeUser(r.Context(), demoRealm, sess.UserID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setDemoCookie(w, "", -1)
	http.Redirect(w, r, "/demo/login", http.StatusSeeOther)
}

func (s *Server) renderDemo(w http.ResponseWriter, t *template.Template, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := t.Execute(w, data); err != nil {
		s.cfg.Logger.Error("demo render", "err", err)
	}
}

func clientIP(r *http.Request) string {
	return r.RemoteAddr
}
