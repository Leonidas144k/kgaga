package ledger

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/Leonidas144k/kgaga/internal/audit"
)

const maxIncidentReplayBytes = 16 << 20
const maxIncidentReplayEvents = 16384

// IncidentHistory returns only incident transitions from the currently open,
// verified, single-writer journal. The caller must have opened this journal
// with an independently trusted expected Head. It verifies ALL records and
// the observed Head before returning any event; it never trusts an arbitrary
// event slice or a bare local checkpoint snapshot.
//
// This bounded in-memory preview has no external trust anchor, hostile-writer
// containment, distributed transaction, or automated crash recovery.
func (a *AnchoredJournal) IncidentHistory(limit int) ([]audit.Event, Head, error) {
	if a == nil || limit < 1 || limit > maxIncidentReplayEvents {
		return nil, Head{}, ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed || a.closed || a.journal == nil || a.checkpoint == nil {
		return nil, Head{}, ErrAnchor
	}
	fail := func() ([]audit.Event, Head, error) {
		a.failed = true
		return nil, Head{}, ErrCorrupt
	}
	journalHead, err := a.journal.Head()
	if err != nil {
		return fail()
	}
	checkpointHead, err := a.checkpoint.Head()
	if err != nil || journalHead != checkpointHead {
		return fail()
	}
	file := a.journal.file
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail()
	}
	blob, err := io.ReadAll(io.LimitReader(file, maxIncidentReplayBytes+1))
	_, restoreErr := file.Seek(0, io.SeekEnd)
	if err != nil || restoreErr != nil || len(blob) > maxIncidentReplayBytes {
		return fail()
	}
	actual, err := Verify(bytes.NewReader(blob), a.journal.chain.key, a.journal.chain.id)
	if err != nil || actual != journalHead {
		return fail()
	}
	rows := bytes.Split(blob, []byte{'\n'})
	var events []audit.Event
	for _, line := range rows {
		if len(line) == 0 {
			continue
		}
		var rec record
		if err := json.Unmarshal(line, &rec); err != nil {
			return fail()
		}
		if rec.Event.Action != "sentinel_incident" {
			continue
		}
		if len(events) >= limit {
			return fail()
		}
		events = append(events, rec.Event)
	}
	stillHead, err := a.journal.Head()
	if err != nil || stillHead != journalHead {
		return fail()
	}
	stillCheckpoint, err := a.checkpoint.Head()
	if err != nil || stillCheckpoint != journalHead {
		return fail()
	}
	return events, journalHead, nil
}
