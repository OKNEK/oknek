package gpuwatch

import (
	"strings"
	"testing"

	"github.com/oknek/oknek/internal/rules"
)

func TestDeanLine_ResolvedIncludesDraft(t *testing.T) {
	p := rules.CostAnomalyPayload{
		Provider: "runpod", PodID: "w411-radar2", Service: "radar-plant",
		DownSince: 1_700_000_000, DownSeconds: 15360, HourlyUSD: 0.79, ExposureUSD: 3.37,
		Resolved: true,
	}
	line := deanLine(p, "DRAFT-TEXT")
	for _, want := range []string{"w411-radar2", "radar-plant", "4h16m", "$3.37", "DRAFT-TEXT"} {
		if !strings.Contains(line, want) {
			t.Errorf("dean line missing %q: %s", want, line)
		}
	}
}

func TestDeanLine_LiveAlertOmitsDraft(t *testing.T) {
	p := rules.CostAnomalyPayload{PodID: "p", Service: "s", DownSeconds: 330, Resolved: false}
	line := deanLine(p, "")
	if strings.Contains(line, "Clawback draft") {
		t.Errorf("live alert should not include a draft block: %s", line)
	}
}
