// Package generator
package generator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type Config struct {
	TextDeny    []string
	JSONDeny    []string
	TextAllow   []string
	JSONAllow   []string
	SecureLocal []string // local domain list (secureDomains)

	TextDenyOut  string
	JSONDenyOut  string
	TextAllowOut string
	JSONAllowOut string
}

// Run downloads sources, merges, cleans, and writes output lists.
// It returns final deny/allow counts and a combined error (if any fetches failed).
func Run(ctx context.Context, cfg Config) (denyCount, allowCount int, err error) {
	deny, derr := obtainAllDomains(ctx, cfg.TextDeny, cfg.JSONDeny)
	allow, aerr := obtainAllDomains(ctx, cfg.TextAllow, cfg.JSONAllow)

	if derr != nil || aerr != nil {
		// combine partial errors but continue
		var parts []string
		if derr != nil {
			parts = append(parts, derr.Error())
		}
		if aerr != nil {
			parts = append(parts, aerr.Error())
		}
		err = errors.New(strings.Join(parts, "; "))
	}

	deny = normalizeAndFilter(deny)
	allow = normalizeAndFilter(allow)
	secure := normalizeAndFilter(cfg.SecureLocal)

	deny = cleanDomains(deny)
	allow = cleanDomains(allow)
	secure = cleanDomains(secure)

	deny = removeSecureDomainsByETLD1(deny, secure)
	deny = difference(uniqueSorted(deny), uniqueSorted(allow))
	allow = uniqueSorted(append(allow, secure...))

	if werr := writeOutputs(cfg, deny, allow); werr != nil {
		if err != nil {
			return 0, 0, fmt.Errorf("%v; %w", err, werr)
		}
		return 0, 0, werr
	}
	return len(deny), len(allow), err
}

func obtainAllDomains(ctx context.Context, textURLs, jsonURLs []string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	var out []string
	var errs []string

	for _, u := range textURLs {
		if strings.HasPrefix(u, "#") || strings.TrimSpace(u) == "" {
			continue
		}
		lines, err := fetchTextLines(ctx, client, u)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", u, err))
			continue
		}
		out = append(out, lines...)
	}
	for _, u := range jsonURLs {
		if strings.HasPrefix(u, "#") || strings.TrimSpace(u) == "" {
			continue
		}
		arr, err := fetchJSONStrings(ctx, client, u)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", u, err))
			continue
		}
		out = append(out, arr...)
	}
	if len(errs) > 0 {
		return out, errors.New(strings.Join(errs, "; "))
	}
	return out, nil
}

func fetchTextLines(ctx context.Context, client *http.Client, url string) ([]string, error) {
	b, err := fetch(ctx, client, url)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(b), "\n"), nil
}

func fetchJSONStrings(ctx context.Context, client *http.Client, url string) ([]string, error) {
	b, err := fetch(ctx, client, url)
	if err != nil {
		return nil, err
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	return arr, nil
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	var lastErr error
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
        req.Header.Set("User-Agent", "disposable-email-domains/1.0 (+github.com/ilyasaftr/disposable-email-domains)")
		resp, err := client.Do(req)
		if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			defer resp.Body.Close()
			return io.ReadAll(io.LimitReader(resp.Body, 10<<20))
		}
		if resp != nil {
			lastErr = fmt.Errorf("http %d", resp.StatusCode)
			resp.Body.Close()
		} else {
			lastErr = err
		}
		select {
		case <-time.After(time.Duration(i+1) * 500 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func normalizeAndFilter(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	return out
}

func cleanDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimPrefix(s, "*.")
		s = strings.TrimPrefix(s, ".")
		out = append(out, s)
	}
	return out
}

func removeSecureDomainsByETLD1(deny, secure []string) []string {
	sec := make(map[string]struct{}, len(secure))
	for _, s := range secure {
		if et, err := effectiveTLDPlusOne(s); err == nil {
			sec[et] = struct{}{}
		} else {
			sec[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(deny))
	for _, d := range deny {
		et, err := effectiveTLDPlusOne(d)
		if err != nil {
			et = d
		}
		if _, ok := sec[et]; ok {
			continue
		}
		out = append(out, d)
	}
	return out
}

func effectiveTLDPlusOne(domain string) (string, error) {
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", fmt.Errorf("empty domain")
	}
	return publicsuffix.EffectiveTLDPlusOne(domain)
}

func uniqueSorted(in []string) []string {
	set := make(map[string]struct{}, len(in))
	for _, s := range in {
		if s != "" {
			set[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func difference(a, b []string) []string {
	sb := make(map[string]struct{}, len(b))
	for _, s := range b {
		sb[s] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, s := range a {
		if _, ok := sb[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}

func writeOutputs(cfg Config, deny, allow []string) error {
	if err := writeText(cfg.TextDenyOut, deny); err != nil {
		return err
	}
	if err := writeJSON(cfg.JSONDenyOut, deny); err != nil {
		return err
	}
	if err := writeText(cfg.TextAllowOut, allow); err != nil {
		return err
	}
	if err := writeJSON(cfg.JSONAllowOut, allow); err != nil {
		return err
	}
	return nil
}

func writeText(path string, lines []string) error {
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}

func writeJSON(path string, arr []string) error {
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func ensureDir(dir string) error {
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}
