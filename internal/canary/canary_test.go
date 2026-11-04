package canary

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shivashis-adhikari/keyfold/internal/fakeshop"
	"github.com/shivashis-adhikari/keyfold/internal/gen"
	"github.com/shivashis-adhikari/keyfold/internal/logs"
	"github.com/shivashis-adhikari/keyfold/internal/plan"
	"github.com/shivashis-adhikari/keyfold/internal/probe"
	"github.com/shivashis-adhikari/keyfold/internal/routes"
	"github.com/shivashis-adhikari/keyfold/internal/synth"
)

// a toy cdn: caches anything the origin marks public, keyed by whatever
// plan it was given.
type fakeCDN struct {
	origin *url.URL
	keyer  *plan.Keyer
	mu     sync.Mutex
	store  map[string]stored
}

type stored struct {
	status int
	header http.Header
	body   []byte
}

func newFakeCDN(origin string, p *plan.Plan) *fakeCDN {
	u, _ := url.Parse(origin)
	return &fakeCDN{origin: u, keyer: plan.NewKeyer(p), store: map[string]stored{}}
}

func (c *fakeCDN) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &logs.Record{Scheme: "https", Host: strings.ToLower(r.Host), Path: r.URL.EscapedPath(), RawQuery: r.URL.RawQuery,
		Header: map[string]string{}, Cookies: map[string]string{}}
	for k := range r.Header {
		rec.Header[strings.ToLower(k)] = r.Header.Get(k)
	}
	for _, ck := range r.Cookies() {
		rec.Cookies[ck.Name] = ck.Value
	}
	c.mu.Lock()
	key := string(c.keyer.Proposed(rec, c.keyer.Route(rec), nil))
	s, ok := c.store[key]
	c.mu.Unlock()
	if !ok {
		req, _ := http.NewRequest("GET", c.origin.String()+r.URL.RequestURI(), nil)
		req.Header = r.Header.Clone()
		req.Host = r.Host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		s = stored{resp.StatusCode, resp.Header, body}
		if strings.Contains(resp.Header.Get("Cache-Control"), "public") {
			c.mu.Lock()
			c.store[key] = s
			c.mu.Unlock()
		}
		w.Header().Set("X-Cache", "MISS")
	} else {
		w.Header().Set("X-Cache", "HIT")
	}
	for k, vs := range s.header {
		w.Header()[k] = vs
	}
	w.WriteHeader(s.status)
	w.Write(s.body)
}

var (
	shopOnce sync.Once
	shopPlan *plan.Plan
	shopErr  error
)

// logs -> inventory -> probe -> plan, against a fresh fake shop. cached
// across tests since probing takes a couple of seconds.
func goodPlan(t *testing.T) *plan.Plan {
	t.Helper()
	shopOnce.Do(func() {
		var buf bytes.Buffer
		fakeshop.WriteTraffic(&buf, fakeshop.TrafficOptions{Requests: 30000, Format: "cloudflare"})
		path := filepath.Join(os.TempDir(), fmt.Sprintf("keyfold-canary-%d.json", os.Getpid()))
		os.WriteFile(path, buf.Bytes(), 0o644)
		defer os.Remove(path)
		sc := logs.Open([]string{path}, logs.Options{})
		b := routes.NewBuilder(routes.Options{})
		for sc.Scan() {
			b.Add(sc.Record())
		}
		srv := httptest.NewServer(fakeshop.New())
		defer srv.Close()
		origin, _ := url.Parse(srv.URL)
		rep, err := probe.Run(context.Background(), b.Finish(), probe.Options{Origin: origin, HostHeader: fakeshop.Host, Rate: 5000, Concurrency: 8, Client: srv.Client()})
		if err != nil {
			shopErr = err
			return
		}
		shopPlan = synth.Synthesize(rep, synth.Options{})
	})
	if shopErr != nil {
		t.Fatal(shopErr)
	}
	return shopPlan
}

// the same plan with color moved out of the product key: the mistake the
// canary exists to catch.
func badPlan(t *testing.T) *plan.Plan {
	p := *goodPlan(t)
	p.Routes = nil
	for _, r := range goodPlan(t).Routes {
		c := *r
		if c.Pattern == "/products/{slug}" {
			c.Query.Keep = slices.DeleteFunc(slices.Clone(c.Query.Keep), func(s string) bool { return s == "color" })
			c.Query.Drop = append(slices.Clone(c.Query.Drop), "color")
		}
		p.Routes = append(p.Routes, &c)
	}
	return &p
}

func record(t *testing.T, p *plan.Plan, originURL string) *Snapshot {
	t.Helper()
	u, _ := url.Parse(originURL)
	snap, err := Record(context.Background(), p, Options{Target: u, HostHeader: fakeshop.Host, Rate: 2000})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func verify(t *testing.T, snap *Snapshot, edge string) *Report {
	t.Helper()
	u, _ := url.Parse(edge)
	rep, err := Verify(context.Background(), snap, VerifyOptions{Options: Options{Target: u, HostHeader: fakeshop.Host, Rate: 2000}})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func logMismatches(t *testing.T, rep *Report) {
	t.Helper()
	var b strings.Builder
	rep.Print(&b)
	t.Log("\n" + b.String())
}

func TestGroups(t *testing.T) {
	p := goodPlan(t)
	groups := Groups(p, 2, 4)
	kinds := map[string]int{}
	for _, g := range groups {
		for _, e := range g.Entries {
			kinds[e.Kind]++
			if e.Kind == Base && strings.Contains(e.URI, "utm_") {
				t.Errorf("base url should have dropped params removed: %s", e.URI)
			}
		}
	}
	if kinds[Base] == 0 || kinds[Merge] == 0 || kinds[Split] == 0 {
		t.Errorf("entry kinds: %v", kinds)
	}
}

func TestCanaryWithPlanKeyedCache(t *testing.T) {
	origin := httptest.NewServer(fakeshop.New())
	defer origin.Close()
	snap := record(t, goodPlan(t), origin.URL)

	good := httptest.NewServer(newFakeCDN(origin.URL, goodPlan(t)))
	defer good.Close()
	rep := verify(t, snap, good.URL)
	if rep.Mismatches != 0 || rep.Errors != 0 {
		logMismatches(t, rep)
		t.Errorf("correct plan: %d mismatches, %d errors", rep.Mismatches, rep.Errors)
	}
	if rep.MergeHits == 0 || rep.MergeHits < rep.Merges/2 {
		t.Errorf("merge siblings should mostly hit the base's entry: %d of %d", rep.MergeHits, rep.Merges)
	}

	// the bad plan's own canary run catches its own mistake: color is now
	// a "merge" param, so color=red gets the base page from cache
	badSnap := record(t, badPlan(t), origin.URL)
	bad := httptest.NewServer(newFakeCDN(origin.URL, badPlan(t)))
	defer bad.Close()
	rep = verify(t, badSnap, bad.URL)
	if rep.Mismatches == 0 {
		logMismatches(t, rep)
		t.Fatal("dropping color should have been caught")
	}
	for _, r := range rep.Results {
		if r.Status == Mismatch && !strings.Contains(r.URI, "color") && !strings.Contains(r.URI, "/products/") {
			t.Errorf("unexpected mismatch outside the products route: %+v", r)
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %d", port)
}

func lookBinary(t *testing.T, env, name string, fallback ...string) string {
	t.Helper()
	if p := os.Getenv(env); p != "" {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, f := range fallback {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	t.Skipf("%s not found, set %s to run against a real %s", name, env, name)
	return ""
}

// starts caddy, built with the cache handler, in front of the origin using
// the generated caddyfile.
func startCaddy(t *testing.T, p *plan.Plan, origin string) string {
	caddy := lookBinary(t, "KEYFOLD_CADDY", "caddy")
	snippet, _, err := gen.Caddy(p, gen.Options{})
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	dir := t.TempDir()
	cfg := strings.Replace(string(snippet), "{\n\tcache {", "{\n\tadmin off\n\tcache {", 1)
	cfg += fmt.Sprintf("\nhttp://:%d {\n\timport keyfold_cache\n\treverse_proxy %s\n}\n", port, strings.TrimPrefix(origin, "http://"))
	os.WriteFile(filepath.Join(dir, "Caddyfile"), []byte(cfg), 0o644)
	cmd := exec.Command(caddy, "run", "--config", filepath.Join(dir, "Caddyfile"), "--adapter", "caddyfile")
	cmd.Env = append(os.Environ(), "HOME="+dir, "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("caddy output:\n%s\nconfig:\n%s", out.String(), cfg)
		}
	})
	waitPort(t, port)
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

func TestCanaryThroughCaddy(t *testing.T) {
	if testing.Short() {
		t.Skip("starts caddy")
	}
	origin := httptest.NewServer(fakeshop.New())
	defer origin.Close()

	snap := record(t, goodPlan(t), origin.URL)
	rep := verify(t, snap, startCaddy(t, goodPlan(t), origin.URL))
	logMismatches(t, rep)
	if rep.Mismatches != 0 || rep.Errors != 0 {
		t.Errorf("caddy with the generated config: %d mismatches, %d errors", rep.Mismatches, rep.Errors)
	}
	if rep.MergeHits == 0 {
		t.Errorf("caddy never served a merge sibling from cache (%d siblings)", rep.Merges)
	}

	badSnap := record(t, badPlan(t), origin.URL)
	rep = verify(t, badSnap, startCaddy(t, badPlan(t), origin.URL))
	if rep.Mismatches == 0 {
		logMismatches(t, rep)
		t.Error("caddy with color dropped from the key should fail the canary")
	}
}

func startNginx(t *testing.T, p *plan.Plan, origin string) string {
	nginx := lookBinary(t, "KEYFOLD_NGINX", "nginx", "/usr/sbin/nginx")
	maps, _, err := gen.Nginx(p, gen.Options{})
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "keyfold.conf"), maps, 0o644)
	conf := fmt.Sprintf(`daemon off;
master_process off;
pid %[1]s/nginx.pid;
error_log %[1]s/error.log;
events {}
http {
	access_log off;
	proxy_cache_path %[1]s/cache keys_zone=kf:10m;
	include %[1]s/keyfold.conf;
	server {
		listen 127.0.0.1:%[2]d;
		location / {
			proxy_cache kf;
			proxy_cache_key $keyfold_cache_key;
			proxy_set_header Host $host;
			add_header X-Cache $upstream_cache_status always;
			proxy_pass %[3]s;
		}
	}
}
`, dir, port, origin)
	os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(conf), 0o644)
	cmd := exec.Command(nginx, "-p", dir, "-c", filepath.Join(dir, "nginx.conf"))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			log, _ := os.ReadFile(filepath.Join(dir, "error.log"))
			t.Logf("nginx output:\n%s\n%s", out.String(), log)
		}
	})
	waitPort(t, port)
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

func TestCanaryThroughNginx(t *testing.T) {
	if testing.Short() {
		t.Skip("starts nginx")
	}
	origin := httptest.NewServer(fakeshop.New())
	defer origin.Close()

	snap := record(t, goodPlan(t), origin.URL)
	rep := verify(t, snap, startNginx(t, goodPlan(t), origin.URL))
	logMismatches(t, rep)
	if rep.Mismatches != 0 || rep.Errors != 0 {
		t.Errorf("nginx with the generated config: %d mismatches, %d errors", rep.Mismatches, rep.Errors)
	}
	if rep.MergeHits == 0 {
		t.Errorf("nginx never served a merge sibling from cache (%d siblings)", rep.Merges)
	}

	badSnap := record(t, badPlan(t), origin.URL)
	rep = verify(t, badSnap, startNginx(t, badPlan(t), origin.URL))
	if rep.Mismatches == 0 {
		logMismatches(t, rep)
		t.Error("nginx with color dropped from the key should fail the canary")
	}
}
