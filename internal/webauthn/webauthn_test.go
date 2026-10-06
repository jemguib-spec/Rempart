package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sort"
	"testing"
)

// ---- encodeur CBOR minimal pour simuler un authentificateur ----

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	case n < 65536:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	}
	return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
}

func enc(v any) []byte {
	switch x := v.(type) {
	case int:
		if x >= 0 {
			return cborHead(0, uint64(x))
		}
		return cborHead(1, uint64(-1-x))
	case []byte:
		return append(cborHead(2, uint64(len(x))), x...)
	case string:
		return append(cborHead(3, uint64(len(x))), x...)
	case map[any]any:
		keys := make([]any, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return string(enc(keys[i])) < string(enc(keys[j])) })
		out := cborHead(5, uint64(len(x)))
		for _, k := range keys {
			out = append(out, enc(k)...)
			out = append(out, enc(x[k])...)
		}
		return out
	}
	panic("type")
}

type authenticator struct {
	alg    int
	signer crypto.Signer
	credID []byte
	count  uint32
	flags  byte
	cose   []byte
}

func newAuthenticator(t *testing.T, alg int) *authenticator {
	a := &authenticator{alg: alg, credID: make([]byte, 16), flags: flagUP | flagUV}
	_, _ = rand.Read(a.credID)
	switch alg {
	case AlgES256:
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		a.signer = k
		x, y := make([]byte, 32), make([]byte, 32)
		k.X.FillBytes(x)
		k.Y.FillBytes(y)
		a.cose = enc(map[any]any{1: 2, 3: AlgES256, -1: 1, -2: x, -3: y})
	case AlgEdDSA:
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		a.signer = priv
		a.cose = enc(map[any]any{1: 1, 3: AlgEdDSA, -1: 6, -2: []byte(pub)})
	case AlgRS256:
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		a.signer = k
		a.cose = enc(map[any]any{1: 3, 3: AlgRS256, -1: k.N.Bytes(), -2: []byte{1, 0, 1}})
	}
	return a
}

func (a *authenticator) authData(rpID string, withCred bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	f := a.flags
	if withCred {
		f |= flagAT
	}
	out = append(out, f)
	out = binary.BigEndian.AppendUint32(out, a.count)
	if withCred {
		out = append(out, make([]byte, 16)...) // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
		out = append(out, a.credID...)
		out = append(out, a.cose...)
	}
	return out
}

func clientJSON(typ string, challenge []byte, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": b64.EncodeToString(challenge), "origin": origin})
	return b
}

func (a *authenticator) register(rpID, origin string, challenge []byte) Registration {
	att := enc(map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": a.authData(rpID, true)})
	return Registration{ClientDataJSON: clientJSON("webauthn.create", challenge, origin), AttestationObject: att}
}

func (a *authenticator) assert(rpID, origin string, challenge []byte) Assertion {
	a.count++
	ad := a.authData(rpID, false)
	cd := clientJSON("webauthn.get", challenge, origin)
	h := sha256.Sum256(cd)
	signed := append(append([]byte{}, ad...), h[:]...)
	var sig []byte
	switch k := a.signer.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, signed)
	default:
		d := sha256.Sum256(signed)
		sig, _ = a.signer.Sign(rand.Reader, d[:], crypto.SHA256)
	}
	return Assertion{CredentialID: a.credID, ClientDataJSON: cd, AuthenticatorData: ad, Signature: sig}
}

const rp, origin = "rempart.lan", "https://rempart.lan:8080"

func TestRegisterAndAssert(t *testing.T) {
	for _, alg := range []int{AlgES256, AlgEdDSA, AlgRS256} {
		a := newAuthenticator(t, alg)
		ch := []byte("défi-inscription-0123456789abcdef")
		cred, err := VerifyRegistration(a.register(rp, origin, ch), ch, rp, origin, false)
		if err != nil {
			t.Fatalf("alg %d : %v", alg, err)
		}
		if cred.Alg != alg || string(cred.ID) != string(a.credID) {
			t.Fatalf("alg %d : %+v", alg, cred)
		}
		ch2 := []byte("défi-connexion-abcdef0123456789")
		n, err := VerifyAssertion(a.assert(rp, origin, ch2), *cred, ch2, rp, origin, true)
		if err != nil || n != 1 {
			t.Fatalf("alg %d : assertion %v (%d)", alg, err, n)
		}
	}
}

func TestRegistrationRejects(t *testing.T) {
	a := newAuthenticator(t, AlgES256)
	ch := []byte("0123456789abcdef0123456789abcdef")
	cases := map[string]func() (Registration, []byte, string, string){
		"autre défi": func() (Registration, []byte, string, string) {
			return a.register(rp, origin, []byte("x")), ch, rp, origin
		},
		"autre origine": func() (Registration, []byte, string, string) {
			return a.register(rp, "https://evil.example", ch), ch, rp, origin
		},
		"autre rpId": func() (Registration, []byte, string, string) {
			return a.register("evil.example", origin, ch), ch, rp, origin
		},
		"type get": func() (Registration, []byte, string, string) {
			r := a.register(rp, origin, ch)
			r.ClientDataJSON = clientJSON("webauthn.get", ch, origin)
			return r, ch, rp, origin
		},
		"CBOR tronqué": func() (Registration, []byte, string, string) {
			r := a.register(rp, origin, ch)
			r.AttestationObject = r.AttestationObject[:len(r.AttestationObject)-5]
			return r, ch, rp, origin
		},
	}
	for name, mk := range cases {
		r, c, rid, o := mk()
		if _, err := VerifyRegistration(r, c, rid, o, false); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	// Sans présence de l'utilisateur.
	a.flags = 0
	if _, err := VerifyRegistration(a.register(rp, origin, ch), ch, rp, origin, false); err == nil {
		t.Error("inscription sans présence acceptée")
	}
}

func TestAssertionRejects(t *testing.T) {
	a := newAuthenticator(t, AlgES256)
	ch := []byte("0123456789abcdef0123456789abcdef")
	cred, err := VerifyRegistration(a.register(rp, origin, ch), ch, rp, origin, false)
	if err != nil {
		t.Fatal(err)
	}
	as := a.assert(rp, origin, ch)
	if _, err := VerifyAssertion(as, *cred, []byte("autre"), rp, origin, false); err == nil {
		t.Error("autre défi accepté")
	}
	bad := as
	bad.Signature = append([]byte{}, as.Signature...)
	bad.Signature[len(bad.Signature)-1] ^= 1
	if _, err := VerifyAssertion(bad, *cred, ch, rp, origin, false); err == nil {
		t.Error("signature altérée acceptée")
	}
	bad = as
	bad.AuthenticatorData = append([]byte{}, as.AuthenticatorData...)
	bad.AuthenticatorData[32] |= flagBS // modifie les données signées
	if _, err := VerifyAssertion(bad, *cred, ch, rp, origin, false); err == nil {
		t.Error("données d'authentification altérées acceptées")
	}
	// Compteur : un rejeu (même compteur) est refusé.
	n, err := VerifyAssertion(as, *cred, ch, rp, origin, false)
	if err != nil {
		t.Fatal(err)
	}
	cred.SignCount = n
	if _, err := VerifyAssertion(as, *cred, ch, rp, origin, false); err == nil {
		t.Error("compteur non progressif accepté (clone ou rejeu)")
	}
	// UV exigé pour une connexion sans mot de passe.
	a.flags = flagUP
	as2 := a.assert(rp, origin, ch)
	if _, err := VerifyAssertion(as2, *cred, ch, rp, origin, true); err == nil {
		t.Error("connexion sans vérification de l'utilisateur acceptée")
	}
	if _, err := VerifyAssertion(as2, *cred, ch, rp, origin, false); err != nil {
		t.Errorf("second facteur avec présence seule : %v", err)
	}
	other := newAuthenticator(t, AlgES256)
	if _, err := VerifyAssertion(other.assert(rp, origin, ch), *cred, ch, rp, origin, false); err == nil {
		t.Error("autre clé acceptée")
	}
}

func TestPasskeyZeroCounter(t *testing.T) {
	// Les passkeys synchronisées gardent un compteur nul.
	a := newAuthenticator(t, AlgES256)
	a.flags |= flagBE | flagBS
	ch := []byte("0123456789abcdef0123456789abcdef")
	cred, err := VerifyRegistration(a.register(rp, origin, ch), ch, rp, origin, false)
	if err != nil || !cred.BackupEligible {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		a.count = 0
		as := a.assert(rp, origin, ch)
		a.count = 0
		as.AuthenticatorData = a.authData(rp, false)
		cd := as.ClientDataJSON
		h := sha256.Sum256(cd)
		d := sha256.Sum256(append(append([]byte{}, as.AuthenticatorData...), h[:]...))
		as.Signature, _ = a.signer.Sign(rand.Reader, d[:], crypto.SHA256)
		if _, err := VerifyAssertion(as, *cred, ch, rp, origin, true); err != nil {
			t.Fatalf("compteur nul : %v", err)
		}
	}
}

func FuzzCBOR(f *testing.F) {
	f.Add(enc(map[any]any{1: 2, "a": []byte{1}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = decodeCBOR(b)
		_, _ = parseAuthData(b, false)
		_, _, _ = coseToPublicKey(b)
	})
}

func TestCBORHugeLengths(t *testing.T) {
	for _, b := range [][]byte{
		{0xbb, 0x80, 0, 0, 0, 0, 0, 0, 0}, // table de 2^63 éléments
		{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		if _, _, err := decodeCBOR(b); err == nil {
			t.Fatalf("%x accepté", b)
		}
	}
}
