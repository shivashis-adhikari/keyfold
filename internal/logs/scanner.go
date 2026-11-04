package logs

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
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
}

type lineParser interface {
	parse(line []byte, rec *Record) error
}

// how many parse errors to keep around for the summary.
const keepErrors = 5

// reads records from one or more log files in order. gzip input is
// detected from the magic bytes, and "-" reads stdin.
//
// the record returned by record() is overwritten by the next call to scan().
// its maps are fresh on every line, so a shallow copy is safe to keep.
type Scanner struct {
	opts  Options
	paths []string

	file   io.Closer
	lines  *bufio.Scanner
	parser lineParser
	name   string
	lineNo int64

	rec Record
	err error

	Lines   int64
	Skipped int64
	Errors  []string
}

// returns a scanner over the given files. nothing is opened until the
// first call to scan.
func Open(paths []string, opts Options) *Scanner {
	if len(paths) == 0 {
		paths = []string{"-"}
	}
	return &Scanner{opts: opts, paths: paths}
}

func (s *Scanner) Scan() bool {
	for s.err == nil {
		if s.lines == nil {
			if len(s.paths) == 0 {
				return false
			}
			if err := s.next(); err != nil {
				s.err = err
				return false
			}
			continue
		}
		if !s.lines.Scan() {
			if err := s.lines.Err(); err != nil {
				s.err = fmt.Errorf("%s: %w", s.name, err)
			}
			s.closeFile()
			continue
		}
		s.lineNo++
		line := bytes.TrimRight(s.lines.Bytes(), "\r ")
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		s.Lines++
		s.rec = Record{}
		if err := s.parser.parse(line, &s.rec); err != nil {
			s.Skipped++
			if len(s.Errors) < keepErrors && !errors.Is(err, errNotAccessLine) {
				s.Errors = append(s.Errors, fmt.Sprintf("%s:%d: %v", s.name, s.lineNo, err))
			}
			continue
		}
		if s.rec.Host == "" {
			s.rec.Host = cleanHost(s.opts.DefaultHost)
		}
		if s.rec.Scheme == "" {
			s.rec.Scheme = s.opts.DefaultScheme
			if s.rec.Scheme == "" {
				s.rec.Scheme = "https"
			}
		}
		if s.rec.Method == "" {
			s.rec.Method = "GET"
		}
		return true
	}
	return false
}

func (s *Scanner) Record() *Record { return &s.rec }

func (s *Scanner) Err() error { return s.err }

func (s *Scanner) Close() error {
	s.closeFile()
	s.paths = nil
	return nil
}

func (s *Scanner) closeFile() {
	if s.file != nil {
		s.file.Close()
	}
	s.file, s.lines, s.parser = nil, nil, nil
}

func (s *Scanner) next() error {
	path := s.paths[0]
	s.paths = s.paths[1:]
	s.name, s.lineNo = path, 0

	var f io.ReadCloser = os.Stdin
	if path != "-" {
		var err error
		if f, err = os.Open(path); err != nil {
			return err
		}
	} else {
		s.name = "stdin"
	}
	br := bufio.NewReaderSize(f, 256<<10)
	var r io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			f.Close()
			return fmt.Errorf("%s: %w", s.name, err)
		}
		r = bufio.NewReaderSize(gz, 256<<10)
	}

	format := s.opts.Format
	if format == Auto {
		peek := r.(*bufio.Reader)
		var err error
		if format, err = sniff(peek); err != nil {
			f.Close()
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	p, err := newParser(format, s.opts.NginxFormat)
	if err != nil {
		f.Close()
		return err
	}

	sc := bufio.NewScanner(r)
	// caddy lines with big header maps get long. 4mb is plenty and still
	// catches a file that isn't line oriented at all.
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	s.file, s.lines, s.parser = f, sc, p
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
