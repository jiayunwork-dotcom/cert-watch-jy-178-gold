// Command cert-watch scans local X.509 certificates (PEM/CRT/DER, single files,
// directories, or globs) and reports how many days until each expires, flagging
// those already expired or within a warning window. It never contacts a CA or
// the network — it only inspects certificates already on disk.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cert-watch/internal/cert"
)

func main() {
	in := flag.String("in", "", "certificate file, directory, or glob (required)")
	warn := flag.Int("warn", 30, "warn when a valid cert expires within this many days")
	strict := flag.Bool("strict", false, "exit 1 if any cert is WARN or EXPIRED")
	out := flag.String("out", "", "output file; empty writes to stdout")
	flag.Parse()

	if *in == "" {
		fatal("missing required -in (certificate file, directory, or glob)")
	}
	inputs, err := resolveInputs(*in)
	if err != nil {
		fatal("%v", err)
	}

	infos, err := cert.LoadAll(inputs, *warn)
	if err != nil {
		fatal("%v", err)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].DaysLeft < infos[j].DaysLeft })

	var b strings.Builder
	fmt.Fprintf(&b, "%-40s %-10s %-12s %s\n", "PATH", "STATUS", "DAYS_LEFT", "SUBJECT/NOT_AFTER")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 80))
	var expired, warnN int
	for _, c := range infos {
		switch c.Status {
		case cert.StatusExpired:
			expired++
		case cert.StatusWarn:
			warnN++
		}
		fmt.Fprintf(&b, "%-40s %-10s %-12d %s (exp %s)\n",
			shortPath(c.Path), c.Status, c.DaysLeft, c.Subject, c.NotAfter.Format("2006-01-02"))
	}
	fmt.Fprintf(&b, "\n%c summary: %d cert(s), %d OK, %d WARN, %d EXPIRED\n",
		' ', len(infos), len(infos)-warnN-expired, warnN, expired)

	if *out == "" {
		fmt.Print(b.String())
	} else if err := os.WriteFile(*out, []byte(b.String()), 0o644); err != nil {
		fatal("write %q: %v", *out, err)
	}

	if *strict && (expired > 0 || warnN > 0) {
		os.Exit(1)
	}
}

func shortPath(p string) string {
	if len(p) <= 40 {
		return p
	}
	return "..." + p[len(p)-37:]
}

func resolveInputs(in string) ([]string, error) {
	if strings.Contains(in, "*") {
		matches, err := filepath.Glob(in)
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no files match %q", in)
		}
		return matches, nil
	}
	info, err := os.Stat(in)
	if err != nil {
		return nil, fmt.Errorf("cannot access -in %q: %w", in, err)
	}
	if !info.IsDir() {
		return []string{in}, nil
	}
	extSet := map[string]bool{".pem": true, ".crt": true, ".cer": true, ".cert": true, ".der": true}
	entries, err := os.ReadDir(in)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !extSet[strings.ToLower(filepath.Ext(e.Name()))] {
			continue
		}
		out = append(out, filepath.Join(in, e.Name()))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate files found in directory %q", in)
	}
	sort.Strings(out)
	return out, nil
}

func fatal(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "cert-watch: "+format+"\n", a...)
	os.Exit(1)
}
