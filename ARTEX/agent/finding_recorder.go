package agent

import (
	"context"

	"github.com/Autumn-27/artex/db"
)

// FindingRecorder is injected by the host; agents never synthesize or copy
// evidence bodies themselves. Its implementation owns the atomic write.
type FindingRecorder interface {
	Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error)
}

// Tool-use guidance is appended without replacing the user's editable prompt.
// It does not require capture or claim that unavailable traffic tools exist.
const findingTrafficGuidance = "\n\n**Finding traffic evidence (optional)**: when calling report_finding, if you have HTTP requests/responses you have viewed and confirmed to support the finding, bind their real IDs in reproduction order with traffic_refs; domain and time are only for shortlisting candidates and do not imply a match. For TCP or other non-HTTP findings, or when nothing was captured or nothing matches exactly, omit it or pass []; keep other verifiable evidence such as command output and logs in evidence, and preferably explain why nothing is bound. Do not guess IDs, and do not re-probe just to capture packets."

func (t *ToolSet) SetFindingRecorder(r FindingRecorder)   { t.findingRecorder = r }
func (w *Worker) SetFindingRecorder(r FindingRecorder)    { w.findingRecorder = r }
func (p *Planner) SetFindingRecorder(r FindingRecorder)   { p.findingRecorder = r }
func (m *MainAgent) SetFindingRecorder(r FindingRecorder) { m.findingRecorder = r }
