package logs

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// how log files are read.
type Options struct {
	Format Format
	// log_format string for nginx logs. empty means combined.
	NginxFormat string
	// used when a line carries no host, which is the norm for nginx's
	// combined format.
	DefaultHost   string
	DefaultScheme string
	// parser goroutines. 0 means one per cpu.
	Workers int
}

type lineParser interface {
	parse(line []byte, rec *Record) error
}

// how many parse errors to keep around for the summary.
const keepErrors = 5

// lines per unit of work handed to a parser goroutine
const batchSize = 2048

// reads records from one or more log files in order. gzip input is
// detected from the magic bytes, and "-" reads stdin.
//
// json decoding is most of the cost of reading cdn logs, so lines are
// parsed on every core in batches and handed back in file order. the record
// returned by record() is overwritten by the next call to scan(). its maps
// are fresh on every line, so a shallow copy is safe to keep.
type Scanner struct {
	opts  Options
	paths []string

	started bool
	order   chan *batch
	stop    chan struct{}

	cur *batch
	pos int
	rec *Record
	err error

	Lines   int64
	Skipped int64
	Errors  []string
}

type batch struct {
	file   string
	parser lineParser
	lines  [][]byte
	nums   []int64
	recs   []Record
	errs   []error
	err    error // file level: couldn't open, bad gzip, read error
	done   chan struct{}
}

// returns a scanner over the given files. nothing is opened until the
// first call to scan.
func Open(paths []string, opts Options) *Scanner {
	if len(paths) == 0 {
		paths = []string{"-"}
	}
	if opts.Workers <= 0 {
		opts.Workers = runtime.GOMAXPROCS(0)
	}
	return &Scanner{opts: opts, paths: paths}
}

func (s *Scanner) start() {
	s.started = true
	work := make(chan *batch, s.opts.Workers)
	s.order = make(chan *batch, 2*s.opts.Workers)
	s.stop = make(chan struct{})
	for i := 0; i < s.opts.Workers; i++ {
		go func() {
			for b := range work {
				b.parse(s.opts)
				close(b.done)
			}
		}()
	}
	go func() {
		defer close(work)
		defer close(s.order)
		for _, p := range s.paths {
			if !s.readFile(p, work) {
				return
			}
		}
	}()
}

// feeds one file to the workers. false means stop everything.
func (s *Scanner) readFile(path string, work chan<- *batch) bool {
	name := path
	if path == "-" {
		name = "stdin"
	}
	send := func(b *batch) bool {
		select {
		case s.order <- b:
		case <-s.stop:
			return false
		}
		if b.err != nil || len(b.lines) == 0 {
			close(b.done)
			return true
		}
		select {
		case work <- b:
			return true
		case <-s.stop:
			return false
		}
	}
	fail := func(err error) bool {
		send(&batch{file: name, err: err, done: make(chan struct{})})
		return false
	}

	var f io.ReadCloser = os.Stdin
	if path != "-" {
		var err error
		if f, err = os.Open(path); err != nil {
			return fail(err)
		}
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 256<<10)
	r := br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", name, err))
		}
		r = bufio.NewReaderSize(gz, 256<<10)
	}
	format := s.opts.Format
	if format == Auto {
		var err error
		if format, err = sniff(r); err != nil {
			return fail(fmt.Errorf("%s: %w", name, err))
		}
	}
	p, err := newParser(format, s.opts.NginxFormat)
	if err != nil {
		return fail(err)
	}

	sc := bufio.NewScanner(r)
	// caddy lines with big header maps get long. 4mb is plenty and still
	// catches a file that isn't line oriented at all.
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var lineNo int64
	b := &batch{file: name, parser: p, done: make(chan struct{})}
	for sc.Scan() {
		lineNo++
		line := bytes.TrimRight(sc.Bytes(), "\r ")
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		b.lines = append(b.lines, append([]byte(nil), line...))
		b.nums = append(b.nums, lineNo)
		if len(b.lines) == batchSize {
			if !send(b) {
				return false
			}
			b = &batch{file: name, parser: p, done: make(chan struct{})}
		}
	}
	if len(b.lines) > 0 && !send(b) {
		return false
	}
	if err := sc.Err(); err != nil {
		return fail(fmt.Errorf("%s: %w", name, err))
	}
	return true
}

func (b *batch) parse(opts Options) {
	b.recs = make([]Record, len(b.lines))
	b.errs = make([]error, len(b.lines))
	host := cleanHost(opts.DefaultHost)
	scheme := opts.DefaultScheme
	if scheme == "" {
		scheme = "https"
	}
	for i, line := range b.lines {
		r := &b.recs[i]
		if err := b.parser.parse(line, r); err != nil {
			b.errs[i] = err
			continue
		}
		if r.Host == "" {
			r.Host = host
		}
		if r.Scheme == "" {
			r.Scheme = scheme
		}
		if r.Method == "" {
			r.Method = "GET"
		}
	}
	b.lines = nil
}

func (s *Scanner) Scan() bool {
	if !s.started {
		s.start()
	}
	for s.err == nil {
		if s.cur != nil && s.pos < len(s.cur.recs) {
			i := s.pos
			s.pos++
			s.Lines++
			if err := s.cur.errs[i]; err != nil {
				s.Skipped++
				if len(s.Errors) < keepErrors && !errors.Is(err, errNotAccessLine) {
					s.Errors = append(s.Errors, fmt.Sprintf("%s:%d: %v", s.cur.file, s.cur.nums[i], err))
				}
				continue
			}
			s.rec = &s.cur.recs[i]
			return true
		}
		b, ok := <-s.order
		if !ok {
			return false
		}
		<-b.done
		if b.err != nil {
			s.err = b.err
			return false
		}
		s.cur, s.pos = b, 0
	}
	return false
}

func (s *Scanner) Record() *Record { return s.rec }

func (s *Scanner) Err() error { return s.err }

// stops the reader and the parsers. safe to call more than once.
func (s *Scanner) Close() error {
	if s.started && s.stop != nil {
		select {
		case <-s.stop:
		default:
			close(s.stop)
		}
		// drain so the reader goroutine can see the stop and exit
		go func(ch chan *batch) {
			for range ch {
			}
		}(s.order)
	}
	return nil
}

func newParser(f Format, nginxFormat string) (lineParser, error) {
	switch f {
	case Cloudflare:
		return cloudflareParser{}, nil
	case Caddy:
		return caddyParser{}, nil
	case Nginx:
		return newNginxParser(nginxFormat)
	}
	return nil, fmt.Errorf("no parser for format %v", f)
}

// guesses the format from the first non-blank line without consuming it.
func sniff(r *bufio.Reader) (Format, error) {
	for n := 4096; ; n *= 2 {
		buf, err := r.Peek(n)
		if len(buf) == 0 {
			if err == io.EOF {
				// empty file, any parser will do
				return Nginx, nil
			}
			return Auto, err
		}
		trimmed := bytes.TrimLeft(buf, " \t\r\n")
		nl := bytes.IndexByte(trimmed, '\n')
		if nl < 0 && err == nil && n < 4<<20 {
			continue // line longer than what we peeked
		}
		line := trimmed
		if nl >= 0 {
			line = trimmed[:nl]
		}
		return sniffLine(line), nil
	}
}

func sniffLine(line []byte) Format {
	if len(line) == 0 || line[0] != '{' {
		return Nginx
	}
	s := string(line)
	switch {
	case strings.Contains(s, `"ClientRequestURI"`), strings.Contains(s, `"EdgeStartTimestamp"`),
		strings.Contains(s, `"ClientRequestPath"`), strings.Contains(s, `"ClientRequestHost"`):
		return Cloudflare
	case strings.Contains(s, `"request"`):
		return Caddy
	}
	// some json we don't know. caddy's parser gives the clearest errors.
	return Caddy
}
