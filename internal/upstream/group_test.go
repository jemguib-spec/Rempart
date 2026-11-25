package upstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fixedUp struct {
	name  string
	delay time.Duration
	fail  bool
}

func (f *fixedUp) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if f.fail {
		return nil, errors.New("échec")
	}
	m := new(dns.Msg)
	m.SetReply(q)
	return m, nil
}
func (f *fixedUp) String() string  { return f.name }
func (f *fixedUp) Encrypted() bool { return true }

// Le résolveur le plus rapide est toujours mis en course ; celui qui échoue
// passe en dernier.
func TestGroupPrefersFastest(t *testing.T) {
	fast := &fixedUp{name: "rapide", delay: time.Millisecond}
	slow := &fixedUp{name: "lent", delay: 40 * time.Millisecond}
	bad := &fixedUp{name: "panne", delay: time.Millisecond, fail: true}
	g, _ := NewGroup([]Upstream{slow, bad, fast})
	q := new(dns.Msg)
	q.SetQuestion("example.", dns.TypeA)
	for i := 0; i < 20; i++ {
		if _, _, err := g.Exchange(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 50; i++ {
		o := g.order()
		if g.members[o[0]].u != fast {
			t.Fatalf("le plus rapide n'est pas en tête : %s", g.members[o[0]].u)
		}
		if g.members[o[len(o)-1]].u != bad && g.members[o[1]].u != bad {
			t.Fatalf("le résolveur en panne n'est pas relégué")
		}
	}
}
