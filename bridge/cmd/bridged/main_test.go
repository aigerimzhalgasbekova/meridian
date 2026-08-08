package main

import (
	"testing"

	"github.com/aikazzh/portfolio/bridge/internal/server"
)

// An assertion is a bearer credential, so a malformed or non-https app
// callback must stop the process at startup, not surface as a silent 400 on
// /login/{p}?app=X the day someone tries to integrate.
func TestParseApps(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantErr bool
	}{
		{name: "empty", spec: ""},
		{name: "one app", spec: "shop=https://shop.example.com/sso/callback"},
		{name: "two apps", spec: "a=https://a.example.com/cb, b=https://b.example.com/cb"},
		{name: "no equals", spec: "https://a.example.com/cb", wantErr: true},
		{name: "no id", spec: "=https://a.example.com/cb", wantErr: true},
		{name: "plain http", spec: "a=http://a.example.com/cb", wantErr: true},
		{name: "relative url", spec: "a=/cb", wantErr: true},
		{name: "no host", spec: "a=https:///cb", wantErr: true},
		{name: "collides with the dev demo app", spec: "demo=https://a.example.com/cb", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apps := map[string]server.App{"demo": {Name: "Demo App", CallbackURL: "http://127.0.0.1:8083/dev/app-callback"}}
			err := parseApps(tt.spec, apps)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseApps(%q) = %v, wantErr %v", tt.spec, err, tt.wantErr)
			}
			if err == nil && tt.spec != "" && len(apps) == 1 {
				t.Fatalf("parseApps(%q) registered nothing", tt.spec)
			}
		})
	}

	apps := map[string]server.App{}
	if err := parseApps("shop=https://shop.example.com/sso/callback", apps); err != nil {
		t.Fatal(err)
	}
	if got := apps["shop"].CallbackURL; got != "https://shop.example.com/sso/callback" {
		t.Fatalf("callback = %q", got)
	}
}
