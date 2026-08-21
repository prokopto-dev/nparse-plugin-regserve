package api

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The brand gates.
//
// The palette in layout.html is measured from nParse+ upstream rather than chosen here — the
// values come from `src/nparseplus/ui/skins.py` by way of `data/assets/icon.svg` (vendored beside
// the templates) and `docs/assets/extra.css`. Two of the rules that travel with it are the ones
// that get broken by somebody with good intentions and a colour picker, so they are gates:
//
//	BRAND001  every foreground/background pair the stylesheet declares clears WCAG AA.
//	BRAND002  no gold value is ever a background.
//
// Both read the stylesheet as TEXT out of the embedded template, so what is checked is what is
// served. Neither can be satisfied by a comment claiming a ratio: BRAND001 recomputes them.

// goldValues are the app's golds. A gold is an ACCENT colour — a link, an active nav item, the
// engraving on the mark — and never a field. #6b5a3a is deliberately absent: it is
// VELIOUS.plate_border, a hairline, and banning it as a background would ban a 1px rule.
var goldValues = map[string]string{
	"#8a7549": "ledger gold",
	"#7d6a42": "ledger gold darkened for a light ground",
	"#e2c882": "velious gold",
	"#c8a951": "duxa gold",
}

// contrastPairs are the foreground/background pairs the stylesheet actually renders, named by
// their custom properties so a token that is re-pointed at a new value is re-measured rather than
// re-reviewed.
//
// AA is 4.5:1 for text. A control's EDGE — an input border, a focus ring — is a non-text
// contrast under WCAG 1.4.11 and its floor is 3:1, which is why --field carries a different
// minimum rather than an exemption.
var contrastPairs = []struct {
	fg, bg string
	min    float64
	what   string
}{
	{fg: "--fg", bg: "--bg", min: 4.5, what: "body text"},
	{fg: "--muted", bg: "--bg", min: 4.5, what: "muted text, which is text"},
	{fg: "--accent", bg: "--bg", min: 4.5, what: "links"},
	{fg: "--warn", bg: "--bg", min: 4.5, what: "a problem notice"},
	{fg: "--field", bg: "--bg", min: 3.0, what: "an input's edge and the focus ring"},

	// The plate is the same slab in both schemes, so these pairs are asserted twice with the same
	// answer. That is not waste: it is what makes re-pointing --plate in one scheme a red test.
	{fg: "--plate-fg", bg: "--plate", min: 4.5, what: "the header's text"},
	{fg: "--plate-muted", bg: "--plate", min: 4.5, what: "the header's muted text"},
	{fg: "--plate-accent", bg: "--plate", min: 4.5, what: "the header's links"},
}

// TestBRAND001_EveryDeclaredPair_ClearsAA is the gate.
//
// It fails with the measured ratio in the message, because the useful thing to know about a
// palette that just went under AA is by how much.
func TestBRAND001_EveryDeclaredPair_ClearsAA(t *testing.T) {
	t.Parallel()

	for _, scheme := range []string{schemeLight, schemeDark} {
		tokens := paletteFor(t, scheme)
		findings, measured := judgeContrast(tokens)
		for _, m := range measured {
			t.Logf("%-5s %s", scheme, m)
		}
		require.NotEmpty(t, measured,
			"BRAND001 measured nothing in the %s scheme; the gate is vacant, not passing", scheme)
		require.Emptyf(t, findings,
			"BRAND001, %s scheme: %s\n\nThe contrast work is done upstream: #7d6a42 on white and "+
				"#e2c882 on the near-black glass are the two values that clear AA, and one value "+
				"cannot do both grounds",
			scheme, strings.Join(findings, "; "))
	}
}

// TestBRAND001_FiresOnThePaletteItExistsToRefuse — the gate has been seen to fail.
//
// The case is the real one rather than an invented one: the ledger gold #8a7549 verbatim, which is
// what somebody reaches for when they read skins.py and take the value at face value. It lands at
// 4.45:1 on white, and the whole reason #7d6a42 exists is that it does.
func TestBRAND001_FiresOnThePaletteItExistsToRefuse(t *testing.T) {
	t.Parallel()

	tokens := paletteFor(t, schemeLight)
	tokens["--accent"] = "#8a7549"

	findings, _ := judgeContrast(tokens)
	require.NotEmpty(t, findings,
		"BRAND001 must refuse the ledger gold on white: it is 4.45:1, which is under AA for "+
			"link-sized text. A gate that accepts it is checking nothing")
	require.Contains(t, strings.Join(findings, "; "), "--accent")
}

// TestBRAND002_NoGold_IsEverAField — "the header is the plate, never the gold".
//
// The app puts gold on accents and engraving, not on large fields; a full-width gold bar is
// off-brand and hard to read against. This resolves every `background` in the stylesheet, through
// as many `var(--…)` hops as it takes and in BOTH schemes, and fails on a gold.
func TestBRAND002_NoGold_IsEverAField(t *testing.T) {
	t.Parallel()

	css := stylesheet(t)
	for _, scheme := range []string{schemeLight, schemeDark} {
		findings, inspected := judgeGoldFields(css, paletteFor(t, scheme))
		require.NotEmpty(t, inspected,
			"BRAND002 found no background declarations; the gate is vacant, not passing")
		require.Emptyf(t, findings,
			"BRAND002, %s scheme: %s\n\nGold goes on links, active nav and focus rings — the "+
				"header is the plate, never the gold",
			scheme, strings.Join(findings, "; "))
	}
}

// TestBRAND002_FiresOnAGoldField — the gate has been seen to fail.
//
// A gold header is the specific mistake this exists for, so the fixture is a header rule painting
// itself with the accent token, which is exactly how it would be written by somebody who thought
// the brand colour belonged on the brand bar.
func TestBRAND002_FiresOnAGoldField(t *testing.T) {
	t.Parallel()

	for _, css := range []string{
		"header { background: var(--accent); }",
		"header { background: #e2c882; }",
		"header { background: linear-gradient(180deg, var(--plate-hi), var(--plate-accent)); }",
		"body { background-color: #8a7549; }",
	} {
		findings, inspected := judgeGoldFields(css, paletteFor(t, schemeLight))
		require.NotEmpty(t, inspected, "nothing was inspected in %q", css)
		require.NotEmptyf(t, findings, "BRAND002 must refuse %q", css)
	}
}

// judgeGoldFields resolves every background in css and returns a finding for each gold one, plus
// what it inspected. Returning findings rather than asserting is what lets the gate and the
// fires-on test above run the same judgement over different input.
func judgeGoldFields(css string, tokens map[string]string) (findings, inspected []string) {
	for _, d := range backgroundDecl.FindAllStringSubmatch(css, -1) {
		value := strings.Join(strings.Fields(d[1]), " ")
		inspected = append(inspected, value)
		for _, colour := range resolve(value, tokens) {
			if name, isGold := goldValues[colour]; isGold {
				findings = append(findings,
					fmt.Sprintf("`background: %s` resolves to %s (%s)", value, colour, name))
			}
		}
	}
	return findings, inspected
}

// judgeContrast measures every declared pair and returns a finding for each one under its floor,
// plus the whole measured table — which is logged, because "by how much" is the useful thing to
// know about a palette that just moved.
func judgeContrast(tokens map[string]string) (findings, measured []string) {
	for _, p := range contrastPairs {
		fg, okFG := tokens[p.fg]
		bg, okBG := tokens[p.bg]
		if !okFG || !okBG {
			findings = append(findings,
				fmt.Sprintf("%s on %s: the stylesheet declares no such token", p.fg, p.bg))
			continue
		}

		ratio, err := contrastRatio(fg, bg)
		if err != nil {
			findings = append(findings, err.Error())
			continue
		}
		measured = append(measured, fmt.Sprintf("%-14s on %-9s %s on %s = %.2f:1 (%s)",
			p.fg, p.bg, fg, bg, ratio, p.what))
		if ratio < p.min {
			findings = append(findings, fmt.Sprintf(
				"%s (%s) on %s (%s) is %.2f:1, under the %.1f:1 %s needs",
				p.fg, fg, p.bg, bg, ratio, p.min, p.what))
		}
	}
	return findings, measured
}

// TestBRAND003_TheMark_IsInlinedFromTheVendoredFile — the header carries the real mark.
//
// It asserts the SVG reaches the page and that it got there by the vendored file being a template,
// which is what keeps the markup from being copied into layout.html by hand. A second copy is a
// copy that drifts, and the drift is invisible: both render.
func TestBRAND003_TheMark_IsInlinedFromTheVendoredFile(t *testing.T) {
	t.Parallel()

	vendored, err := webFiles.ReadFile("webtmpl/assets/" + markTemplate)
	require.NoError(t, err, "the vendored mark must be embedded")
	require.True(t, strings.HasPrefix(string(vendored), "<svg"),
		"the vendored file must still begin with <svg>: librsvg sniffs the format from the first "+
			"bytes, and a leading comment makes it unreadable upstream")

	layout, err := webFiles.ReadFile("webtmpl/layout.html")
	require.NoError(t, err)
	require.Contains(t, string(layout), `{{template "`+markTemplate+`" .}}`,
		"layout.html must INCLUDE the vendored mark rather than restate it")
	require.NotContains(t, string(layout), "<circle",
		"the mark's own markup must not be pasted into the layout")

	rendered, err := renderPage(t.Context(), "directory.html", pageData{Title: "Plugins"})
	require.NoError(t, err)
	body := string(rendered.Body)
	require.Contains(t, body, `viewBox="0 0 256 256"`, "the mark is inlined into the page")
	require.Contains(t, body, "<title>nParse+</title>")
	require.NotContains(t, body, "gdk-pixbuf",
		"html/template elides the vendored file's provenance comment; the page carries the "+
			"markup and the reasoning stays on disk")
}

// markTemplate is the vendored mark's template name, which is its base filename. One spelling, so
// the gate and the layout cannot be talking about different files.
const markTemplate = "nparseplus-mark.svg"

const (
	schemeLight = "light"
	schemeDark  = "dark"
)

var (
	// customProperty matches a custom-property declaration and its colour. It is anchored on the
	// `--name:` so the hexes inside the comments — which name the values being explained — are not
	// mistaken for declarations.
	customProperty = regexp.MustCompile(`--([a-z-]+)\s*:\s*(#[0-9a-fA-F]{3,8})`)

	// backgroundDecl matches a background declaration's whole value, across newlines: the
	// stylesheet wraps at 100 columns and `linear-gradient(...)` does not always fit on one line.
	backgroundDecl = regexp.MustCompile(`(?s)background(?:-color|-image)?\s*:\s*([^;}]*)`)

	varRef = regexp.MustCompile(`var\(\s*(--[a-z-]+)\s*\)`)
	hexRef = regexp.MustCompile(`#[0-9a-fA-F]{3,8}`)

	darkBlock = regexp.MustCompile(`@media\s*\(prefers-color-scheme:\s*dark\)`)
)

// stylesheet returns the <style> block of layout.html, as served.
func stylesheet(t *testing.T) string {
	t.Helper()

	raw, err := webFiles.ReadFile("webtmpl/layout.html")
	require.NoError(t, err)

	open := strings.Index(string(raw), "<style>")
	closed := strings.Index(string(raw), "</style>")
	require.Greater(t, closed, open, "layout.html must carry one <style> block")
	return string(raw)[open+len("<style>") : closed]
}

// paletteFor returns the custom properties in effect for a scheme.
//
// The dark scheme is the light one with the media block's overrides applied, which is what the
// browser does — so a token declared only in :root (the plate) is measured in both, and one
// re-pointed in only one scheme is measured as it renders rather than as it reads.
func paletteFor(t *testing.T, scheme string) map[string]string {
	t.Helper()

	css := stylesheet(t)
	split := len(css)
	if loc := darkBlock.FindStringIndex(css); loc != nil {
		split = loc[0]
	}
	require.Less(t, split, len(css),
		"layout.html must keep its prefers-color-scheme block; both schemes are gated")

	tokens := map[string]string{}
	collect := func(section string) {
		for _, m := range customProperty.FindAllStringSubmatch(section, -1) {
			tokens["--"+m[1]] = strings.ToLower(m[2])
		}
	}
	collect(css[:split])
	if scheme == schemeDark {
		collect(css[split:])
	}
	require.NotEmpty(t, tokens, "BRAND001 read no palette; the gate is vacant, not passing")
	return tokens
}

// resolve expands a declaration's value into the colours it actually paints, following var()
// references. An unresolvable reference is a bug in the stylesheet rather than something to skip
// quietly, so it is returned as-is and fails the caller's lookup on the next pass.
func resolve(value string, tokens map[string]string) []string {
	seen := map[string]bool{}
	// A var() may point at a token whose value is another var(). Three passes is far more than the
	// stylesheet uses and terminates whatever somebody writes.
	for range 3 {
		value = varRef.ReplaceAllStringFunc(value, func(ref string) string {
			name := varRef.FindStringSubmatch(ref)[1]
			if v, ok := tokens[name]; ok {
				return v
			}
			return ref
		})
	}
	var out []string
	for _, h := range hexRef.FindAllString(value, -1) {
		h = strings.ToLower(h)
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// contrastRatio is WCAG 2.1's, over sRGB. Written out rather than pulled in: it is nine lines, and
// a dependency for nine lines is a dependency a human has to approve.
func contrastRatio(a, b string) (float64, error) {
	la, err := relativeLuminance(a)
	if err != nil {
		return 0, err
	}
	lb, err := relativeLuminance(b)
	if err != nil {
		return 0, err
	}
	hi, lo := math.Max(la, lb), math.Min(la, lb)
	return (hi + 0.05) / (lo + 0.05), nil
}

func relativeLuminance(hex string) (float64, error) {
	h := strings.TrimPrefix(strings.ToLower(hex), "#")
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	if len(h) != 6 {
		return 0, fmt.Errorf("parse the colour %q: want #rgb or #rrggbb", hex)
	}

	channel := func(i int) (float64, error) {
		v, err := strconv.ParseUint(h[i:i+2], 16, 8)
		if err != nil {
			return 0, fmt.Errorf("parse the colour %q: %w", hex, err)
		}
		c := float64(v) / 255
		if c <= 0.03928 {
			return c / 12.92, nil
		}
		return math.Pow((c+0.055)/1.055, 2.4), nil
	}

	r, err := channel(0)
	if err != nil {
		return 0, err
	}
	g, err := channel(2)
	if err != nil {
		return 0, err
	}
	bl, err := channel(4)
	if err != nil {
		return 0, err
	}
	return 0.2126*r + 0.7152*g + 0.0722*bl, nil
}
