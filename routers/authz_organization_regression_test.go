// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package routers

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	beegoContext "github.com/beego/beego/v2/server/web/context"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
	"github.com/xorm-io/xorm"
)

type regressionSession map[interface{}]interface{}

func (s regressionSession) Set(_ context.Context, key, value interface{}) error {
	s[key] = value
	return nil
}
func (s regressionSession) Get(_ context.Context, key interface{}) interface{} { return s[key] }
func (s regressionSession) Delete(_ context.Context, key interface{}) error {
	delete(s, key)
	return nil
}
func (s regressionSession) SessionID(context.Context) string                             { return "test-session" }
func (s regressionSession) SessionReleaseIfPresent(context.Context, http.ResponseWriter) {}
func (s regressionSession) SessionRelease(context.Context, http.ResponseWriter)          {}
func (s regressionSession) Flush(context.Context) error                                  { return nil }

func newOrganizationRequest(method, target, body string) (*beegoContext.Context, *httptest.ResponseRecorder) {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(response, request)
	ctx.Input.CruSession = regressionSession{"username": "org-a/admin"}
	RequestBodyFilter(ctx)
	return ctx, response
}

func TestOrganizationAuthorizationRegression(t *testing.T) {
	database := filepath.Join(t.TempDir(), "casdoor.sqlite") + "?_pragma=busy_timeout%3d10000&_pragma=journal_mode%3dWAL"
	t.Setenv("driverName", "sqlite3")
	t.Setenv("dataSourceName", database)
	t.Setenv("dbName", "casdoor")
	t.Setenv("tableNamePrefix", "")
	object.InitAdapter()

	engine, err := xorm.NewEngine("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if err := engine.Sync2(&object.User{}, &object.ThirdPartyLink{}, &object.Permission{}, &object.Provider{}, &object.Record{}, &object.Webhook{}, &object.Application{}, &object.Organization{}, &object.Syncer{}); err != nil {
		t.Fatal(err)
	}
	users := []*object.User{
		{Owner: "org-a", Name: "admin", Id: "admin-id", DisplayName: "Admin", IsAdmin: true},
		{Owner: "org-a", Name: "user", Id: "own-id", DisplayName: "Own name"},
		{Owner: "org-a", Name: "other", Id: "other-id", DisplayName: "Other name"},
		{Owner: "org-b", Name: "victim", Id: "foreign-id", DisplayName: "Original name"},
		{Owner: "built-in", Name: "admin", IsAdmin: true},
	}
	if _, err := engine.Insert(&users); err != nil {
		t.Fatal(err)
	}
	organizations := []*object.Organization{
		{Owner: "admin", Name: "org-a", AccountItems: object.GetDefaultAccountItems()},
		{Owner: "admin", Name: "org-b", AccountItems: object.GetDefaultAccountItems()},
	}
	if _, err := engine.Insert(&organizations); err != nil {
		t.Fatal(err)
	}
	apps := []*object.Application{
		{Owner: "admin", Name: "org-a-private", Organization: "org-a", CreatedTime: "2026-01-01"},
		{Owner: "admin", Name: "org-b-private", Organization: "org-b", CreatedTime: "2026-01-02"},
		{Owner: "admin", Name: "shared", Organization: "org-b", IsShared: true, CreatedTime: "2026-01-03"},
	}
	if _, err := engine.Insert(&apps); err != nil {
		t.Fatal(err)
	}

	// These management endpoints are not public in Casdoor's built-in policy.
	// Keep Casdoor's self-access rule and real admin/API-permission checks,
	// backed by SQLite. The inert policy lets Casbin evaluate the self rule.
	m, err := model.NewModelFromString(`
[request_definition]
r = subOwner, subName, method, urlPath, objOwner, objName
[policy_definition]
p = subOwner, subName, method, urlPath, objOwner, objName
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = (r.subOwner == p.subOwner && r.subName == p.subName && r.method == p.method && r.urlPath == p.urlPath && r.objOwner == p.objOwner && r.objName == p.objName) || (r.subOwner == r.objOwner && r.subName == r.objName)
`)
	if err != nil {
		t.Fatal(err)
	}
	previousEnforcer := authz.Enforcer
	authz.Enforcer, err = casbin.NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { authz.Enforcer = previousEnforcer })
	if _, err := authz.Enforcer.AddPolicy("unused", "unused", "POST", "/unused", "unused", "unused"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, method, target, body string
		allowed                    bool
	}{
		{"body cannot target another organization", "POST", "/api/delete-user?id=org-a/admin", `{"owner":"org-b","name":"victim"}`, false},
		{"query cannot target another organization", "POST", "/api/delete-user?id=org-b/victim", `{"owner":"org-a","name":"admin"}`, false},
		{"same organization mutation remains allowed", "POST", "/api/delete-user?id=org-a/admin", `{"owner":"org-a","name":"admin"}`, true},
		{"organization parameter cannot spoof user list owner", "GET", "/api/get-users?owner=org-b&organization=org-a", "", false},
		{"organization parameter cannot spoof group owner", "GET", "/api/get-group?id=org-b/team&organization=org-a", "", false},
		{"owner parameter cannot spoof another organization count", "GET", "/api/get-user-count?id=org-a/admin&owner=org-b", "", false},
		{"adapter identifier takes precedence over enforcer identifier", "GET", "/api/get-policies?id=org-a/model&adapterId=org-b/adapter", "", false},
		{"organization-scoped application query remains allowed", "GET", "/api/get-applications?owner=admin&organization=org-a", "", true},
		{"own organization count remains allowed", "GET", "/api/get-user-count?owner=org-a", "", true},
		{"another organization's application query is denied", "GET", "/api/get-applications?owner=admin&organization=org-b", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, response := newOrganizationRequest(tc.method, tc.target, tc.body)
			ApiFilter(ctx)
			gotAllowed := !ctx.ResponseWriter.Started
			if gotAllowed != tc.allowed {
				t.Fatalf("allowed=%v, want %v; response=%s", gotAllowed, tc.allowed, response.Body.String())
			}
			if !tc.allowed {
				var payload struct {
					Status string `json:"status"`
					Msg    string `json:"msg"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Status != "error" || payload.Msg != T(ctx, "auth:Unauthorized operation") {
					t.Fatalf("expected Casdoor error response, got %s (decode: %v)", response.Body.String(), err)
				}
			}
		})
	}

	t.Run("userId cannot update another organization's user", func(t *testing.T) {
		ctx, response := newOrganizationRequest("POST", "/api/update-user?id=org-a/admin&owner=org-b&userId=foreign-id&columns=displayName", `{"displayName":"Changed by attacker"}`)
		ApiFilter(ctx)
		if !ctx.ResponseWriter.Started {
			c := &controllers.ApiController{}
			c.Init(ctx, "ApiController", "UpdateUser", c)
			c.UpdateUser()
		}
		user := object.User{Owner: "org-b", Name: "victim"}
		found, err := engine.Get(&user)
		if err != nil || !found {
			t.Fatalf("read foreign user: found=%v, error=%v", found, err)
		}
		if user.DisplayName != "Original name" {
			t.Fatalf("foreign user was modified: displayName=%q, response=%s", user.DisplayName, response.Body.String())
		}
		var payload struct {
			Status string `json:"status"`
			Msg    string `json:"msg"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Status != "error" || payload.Msg != T(ctx, "auth:Unauthorized operation") {
			t.Fatalf("expected authorization denial, got %s (decode: %v)", response.Body.String(), err)
		}
	})

	t.Run("userId cannot update another user in the same organization", func(t *testing.T) {
		ctx, response := newOrganizationRequest("POST", "/api/update-user?id=org-a/user&owner=org-a&userId=other-id&columns=displayName", `{"displayName":"Changed by attacker"}`)
		ctx.Input.CruSession = regressionSession{"username": "org-a/user"}
		ApiFilter(ctx)
		if !ctx.ResponseWriter.Started {
			c := &controllers.ApiController{}
			c.Init(ctx, "ApiController", "UpdateUser", c)
			c.UpdateUser()
		}
		user := object.User{Owner: "org-a", Name: "other"}
		found, err := engine.Get(&user)
		if err != nil || !found {
			t.Fatalf("read other user: found=%v, error=%v", found, err)
		}
		if user.DisplayName != "Other name" {
			t.Fatalf("other user was modified: displayName=%q, response=%s", user.DisplayName, response.Body.String())
		}
		var payload struct {
			Status string `json:"status"`
			Msg    string `json:"msg"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Status != "error" || payload.Msg != T(ctx, "auth:Unauthorized operation") {
			t.Fatalf("expected authorization denial, got %s (decode: %v)", response.Body.String(), err)
		}
	})

	t.Run("user may update own profile by userId", func(t *testing.T) {
		ctx, response := newOrganizationRequest("POST", "/api/update-user?id=org-a/user&owner=org-a&userId=own-id&columns=displayName", `{"displayName":"Updated own name"}`)
		ctx.Input.CruSession = regressionSession{"username": "org-a/user"}
		ApiFilter(ctx)
		if ctx.ResponseWriter.Started {
			t.Fatalf("unexpected authorization denial: %s", response.Body.String())
		}
		c := &controllers.ApiController{}
		c.Init(ctx, "ApiController", "UpdateUser", c)
		c.UpdateUser()
		user := object.User{Owner: "org-a", Name: "user"}
		found, err := engine.Get(&user)
		if err != nil || !found || user.DisplayName != "Updated own name" {
			t.Fatalf("own user update failed: found=%v, displayName=%q, error=%v, response=%s", found, user.DisplayName, err, response.Body.String())
		}
	})

	for _, tc := range []struct {
		name, subject, owner, userId, userName string
	}{
		{"organization admin may update own organization's user", "org-a/admin", "org-a", "other-id", "other"},
		{"global admin may update another organization's user", "built-in/admin", "org-b", "foreign-id", "victim"},
		{"application principal may update another organization's user", "app/test-client", "org-b", "foreign-id", "victim"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := url.Values{"id": {"org-a/admin"}, "owner": {tc.owner}, "userId": {tc.userId}, "columns": {"displayName"}}
			ctx, response := newOrganizationRequest("POST", "/api/update-user?"+query.Encode(), `{"displayName":"Permitted change"}`)
			ctx.Input.CruSession = regressionSession{"username": tc.subject}
			ApiFilter(ctx)
			if ctx.ResponseWriter.Started {
				t.Fatalf("unexpected authorization denial: %s", response.Body.String())
			}
			c := &controllers.ApiController{}
			c.Init(ctx, "ApiController", "UpdateUser", c)
			c.UpdateUser()
			user := object.User{Owner: tc.owner, Name: tc.userName}
			found, err := engine.Get(&user)
			if err != nil || !found || user.DisplayName != "Permitted change" {
				t.Fatalf("authorized update failed: found=%v, displayName=%q, error=%v, response=%s", found, user.DisplayName, err, response.Body.String())
			}
		})
	}

	for _, encoding := range []string{"form", "multipart"} {
		for _, tc := range []struct {
			name, owner, userName string
			allowed               bool
		}{
			{"own organization", "org-a", "admin", true},
			{"foreign organization", "org-b", "victim", false},
		} {
			t.Run(encoding+" MFA "+tc.name, func(t *testing.T) {
				fields := url.Values{"owner": {tc.owner}, "name": {tc.userName}, "mfaType": {"app"}}
				body, contentType := fields.Encode(), "application/x-www-form-urlencoded"
				if encoding == "multipart" {
					var buffer bytes.Buffer
					writer := multipart.NewWriter(&buffer)
					for key, values := range fields {
						if err := writer.WriteField(key, values[0]); err != nil {
							t.Fatal(err)
						}
					}
					if err := writer.Close(); err != nil {
						t.Fatal(err)
					}
					body, contentType = buffer.String(), writer.FormDataContentType()
				}
				ctx, response := newOrganizationRequest("POST", "/api/mfa/setup/initiate?id=org-a/admin", body)
				ctx.Request.Header.Set("Content-Type", contentType)
				ApiFilter(ctx)
				if allowed := !ctx.ResponseWriter.Started; allowed != tc.allowed {
					t.Fatalf("allowed=%v, want %v; response=%s", allowed, tc.allowed, response.Body.String())
				}
				if !tc.allowed {
					var payload struct {
						Status string `json:"status"`
						Msg    string `json:"msg"`
					}
					if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Status != "error" || payload.Msg != T(ctx, "auth:Unauthorized operation") {
						t.Fatalf("expected authorization denial, got %s (decode: %v)", response.Body.String(), err)
					}
				}
			})
		}
	}

	for _, tc := range []struct {
		name, target string
		want         []string
		wantCount    *int
	}{
		{"paginated organization query", "/api/get-applications?owner=admin&organization=org-a&pageSize=10&p=1", []string{"org-a-private", "shared"}, ptrInt(2)},
		{"unpaginated organization query", "/api/get-applications?owner=admin&organization=org-a", []string{"org-a-private", "shared"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, response := newOrganizationRequest("GET", tc.target, "")
			ApiFilter(ctx)
			if ctx.ResponseWriter.Started {
				t.Fatalf("unexpected authorization error: %s", response.Body.String())
			}
			c := &controllers.ApiController{}
			c.Init(ctx, "ApiController", "GetApplications", c)
			c.GetApplications()
			var payload struct {
				Status string `json:"status"`
				Data   []struct {
					Name string `json:"name"`
				} `json:"data"`
				Count *int `json:"data2"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode %s: %v", response.Body.String(), err)
			}
			var names []string
			for _, app := range payload.Data {
				names = append(names, app.Name)
			}
			sort.Strings(names)
			if payload.Status != "ok" || strings.Join(names, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("status=%s apps=%v, want %v", payload.Status, names, tc.want)
			}
			if tc.wantCount != nil && (payload.Count == nil || *payload.Count != *tc.wantCount) {
				t.Fatalf("count=%v, want %d", payload.Count, *tc.wantCount)
			}
		})
	}
}

func ptrInt(v int) *int { return &v }
