package ui

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// renderBarOld reproduces the exact previous implementation (byte-offset slice
// of one combined bar string) so the regression tests can be shown to fail
// against it. It exists only to prove the tests have teeth; it is not used by
// the product.
func renderBarOld(fraction float64, width int) string {
	if width <= 0 {
		width = barWidth
	}
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}
	filled := int(fraction*float64(width) + 0.5)
	if filled > width {
		filled = width
	}
	bar := strings.Repeat(barFull, filled) + strings.Repeat(barEmpty, width-filled)
	switch {
	case filled >= width:
		return styleGood.Render(bar)
	case filled <= 0:
		return styleMuted.Render(bar)
	default:
		return lipgloss.NewStyle().Foreground(colorAccent).Render(bar[:filled]) +
			styleMuted.Render(bar[filled:])
	}
}

// TestOldRenderBarWasCorrupted documents the defect the fix addresses: with
// colour enabled, the old implementation emitted a broken glyph whenever the
// fill count was not a multiple of the 3-byte glyph length. It asserts on the
// OLD function, so it keeps passing no matter how the product code evolves.
func TestOldRenderBarWasCorrupted(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })

	var broken, clean []int
	for filled := 1; filled < 22; filled++ {
		got := renderBarOld(float64(filled)/22, 22)
		if !utf8.ValidString(got) || strings.ContainsRune(got, utf8.RuneError) {
			broken = append(broken, filled)
		} else {
			clean = append(clean, filled)
		}
	}

	t.Logf("旧实现损坏的填充值: %v", broken)
	t.Logf("旧实现侥幸正常的填充值: %v", clean)

	if len(broken) == 0 {
		t.Fatal("预期旧实现会产生损坏输出，但它没有——本回归测试失去意义")
	}
	// The corrupted fills are exactly the non-multiples of three, which is why
	// only some bars looked broken.
	for _, filled := range broken {
		if filled%3 == 0 {
			t.Errorf("filled=%d 是 3 的倍数却被判定损坏，诊断有误", filled)
		}
	}
	for _, filled := range clean {
		if filled%3 != 0 {
			t.Errorf("filled=%d 不是 3 的倍数却被判定正常，诊断有误", filled)
		}
	}

	// The shipped implementation must be clean for every fill count.
	for filled := 0; filled <= 22; filled++ {
		got := renderBar(float64(filled)/22, 22)
		if !utf8.ValidString(got) || strings.ContainsRune(got, utf8.RuneError) {
			t.Fatalf("修复后的实现在 filled=%d 仍然损坏: %q", filled, got)
		}
	}
}
