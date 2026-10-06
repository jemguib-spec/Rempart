package api

import "testing"

func TestHSMCloneGuards(t *testing.T) {
	e := newIDEnv(t)
	adm := e.localAdmin()
	if r, _ := e.do(adm, "POST", "/api/hsm/clone/verify", map[string]string{"module": "/usr/lib/x.so", "token": "t", "pin": "1234"}); r.StatusCode != 400 {
		t.Fatalf("vérification sans HSM en service : %d", r.StatusCode)
	}
	if r, _ := e.do(adm, "POST", "/api/hsm/clone/apply", map[string]string{"module": "/usr/lib/x.so", "token": "t"}); r.StatusCode != 400 {
		t.Fatalf("bascule sans vérification : %d", r.StatusCode)
	}
	read := e.sessionClient(Principal{User: "ldap:lea", Role: RoleOperator, Source: "ldap"})
	if r, _ := e.do(read, "POST", "/api/hsm/clone/apply", map[string]string{"module": "x", "token": "t"}); r.StatusCode != 403 {
		t.Fatalf("opérateur autorisé : %d", r.StatusCode)
	}
}
