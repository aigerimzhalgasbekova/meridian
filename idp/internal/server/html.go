package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"html/template"
	"net/http"
)

func subtleEqual(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// The UI is deliberately dependency-free server-rendered HTML: inline styles
// (the CSP allows nothing else), no JavaScript at all.
var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · Meridian</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; display: grid; place-items: center;
         min-height: 100vh; margin: 0; background: light-dark(#f4f4f5, #18181b);
         color: light-dark(#18181b, #f4f4f5); }
  .card { background: light-dark(#fff, #27272a); border-radius: 12px; padding: 2rem;
          width: min(24rem, 90vw); box-shadow: 0 4px 24px rgba(0,0,0,.08); }
  h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
  p.sub { margin: 0 0 1.5rem; color: light-dark(#52525b, #a1a1aa); font-size: .875rem; }
  label { display: block; font-size: .8125rem; font-weight: 600; margin: 1rem 0 .25rem; }
  input[type=text], input[type=password] { width: 100%; box-sizing: border-box;
    padding: .5rem .75rem; border: 1px solid light-dark(#d4d4d8, #3f3f46);
    border-radius: 8px; font-size: 1rem; background: transparent; color: inherit; }
  button { width: 100%; margin-top: 1.5rem; padding: .625rem; border: 0; border-radius: 8px;
    background: #4f46e5; color: #fff; font-size: 1rem; font-weight: 600; cursor: pointer; }
  button.secondary { background: transparent; color: light-dark(#52525b, #a1a1aa);
    border: 1px solid light-dark(#d4d4d8, #3f3f46); margin-top: .5rem; }
  .error { background: light-dark(#fef2f2, #3f1d1d); color: light-dark(#b91c1c, #fca5a5);
    border-radius: 8px; padding: .625rem .75rem; font-size: .875rem; margin-bottom: 1rem; }
  ul.scopes { padding-left: 1.25rem; font-size: .9375rem; }
  .code { font: 700 1.5rem/1 ui-monospace, monospace; letter-spacing: .1em; text-align: center;
    padding: .75rem; background: light-dark(#f4f4f5, #18181b); border-radius: 8px; }
</style>
</head>
<body><div class="card">{{template "body" .}}</div></body>
</html>`))

var loginTemplate = template.Must(template.Must(pageTemplate.Clone()).Parse(`{{define "body"}}
<h1>Sign in</h1>
<p class="sub">to continue to {{.ClientName}}</p>
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
<form method="post" action="{{.Action}}">
  <input type="hidden" name="csrf_token" value="{{.CSRF}}">
  <input type="hidden" name="return_to" value="{{.ReturnTo}}">
  <label for="username">Username</label>
  <input type="text" id="username" name="username" autocomplete="username" autofocus required>
  <label for="password">Password</label>
  <input type="password" id="password" name="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
</form>
{{end}}`))

var consentTemplate = template.Must(template.Must(pageTemplate.Clone()).Parse(`{{define "body"}}
<h1>Authorize {{.ClientName}}</h1>
<p class="sub">{{.Username}}, this application requests access to:</p>
<ul class="scopes">{{range .ScopeDescriptions}}<li>{{.}}</li>{{end}}</ul>
<form method="post" action="{{.Action}}">
  <input type="hidden" name="csrf_token" value="{{.CSRF}}">
  <input type="hidden" name="return_to" value="{{.ReturnTo}}">
  <button type="submit" name="decision" value="allow">Allow</button>
  <button type="submit" name="decision" value="deny" class="secondary">Deny</button>
</form>
{{end}}`))

var deviceTemplate = template.Must(template.Must(pageTemplate.Clone()).Parse(`{{define "body"}}
<h1>Device sign-in</h1>
<p class="sub">Enter the code shown on your device.</p>
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
<form method="post" action="{{.Action}}">
  <input type="hidden" name="csrf_token" value="{{.CSRF}}">
  <label for="user_code">Code</label>
  <input type="text" id="user_code" name="user_code" value="{{.UserCode}}"
         placeholder="XXXX-XXXX" autocomplete="off" autofocus required>
  <button type="submit" name="decision" value="allow">Approve</button>
  <button type="submit" name="decision" value="deny" class="secondary">Deny</button>
</form>
{{end}}`))

var messageTemplate = template.Must(template.Must(pageTemplate.Clone()).Parse(`{{define "body"}}
<h1>{{.Title}}</h1>
<p class="sub">{{.Message}}</p>
{{if .Code}}<div class="code">{{.Code}}</div>{{end}}
{{end}}`))

// WritePageError renders a protocol error as HTML. Used only when redirecting
// to the client is not safe (unknown client / unvalidated redirect_uri).
func (s *Server) writePageError(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	w.WriteHeader(status)
	_ = messageTemplate.ExecuteTemplate(w, "page", map[string]any{
		"Title": title, "Message": message,
	})
}

func renderTemplate(w http.ResponseWriter, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	_ = t.ExecuteTemplate(w, "page", data)
}

// scopeDescriptions renders human strings for the consent screen.
func scopeDescriptions(scopes []string) []string {
	known := map[string]string{
		"openid":         "Confirm your identity",
		"profile":        "View your basic profile (name, username)",
		"email":          "View your email address",
		"offline_access": "Keep access when you are offline (refresh tokens)",
	}
	out := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		if d, ok := known[sc]; ok {
			out = append(out, d)
		} else {
			out = append(out, "Access scope: "+sc)
		}
	}
	return out
}
