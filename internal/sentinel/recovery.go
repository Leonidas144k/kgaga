package sentinel

import (
	"encoding/hex"
	"time"

	"github.com/Leonidas144k/kgaga/internal/audit"
	"github.com/Leonidas144k/kgaga/internal/ledger"
)

var ErrIncidentHistory = ErrIncidentStorage

func incidentHexID(s string) bool {
	if len(s) != 32 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 16 && hex.EncodeToString(b) == s
}

func replayTime(s string) (time.Time, error) {
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || v.UTC().Format(time.RFC3339Nano) != s {
		return time.Time{}, ErrIncidentHistory
	}
	return v, nil
}

func recoveredAlert(e audit.Event, t time.Time) (Alert, error) {
	severity := "warning"
	if e.IncidentSignal == ResponseWithheldBurst {
		severity = "notice"
	}
	a := Alert{
		Schema: AlertSchema, ObservedAt: e.IncidentObservedAt,
		Signal: e.IncidentSignal, Severity: severity, Advisory: true,
		VaultID: e.VaultID, AgentID: e.AgentID,
		Owner: e.Owner, Audience: e.Audience,
		Count: e.IncidentCount, WindowSeconds: e.IncidentWindowSeconds,
	}
	observed, err := replayTime(a.ObservedAt)
	if err != nil || observed.After(t.Add(time.Minute)) || !validAlert(a, observed) {
		return Alert{}, ErrIncidentHistory
	}
	return a, nil
}

func safeIncidentMetadata(e audit.Event) bool {
	// Reject unauthorised extra event fields: incident reconstruction never
	// needs tokens, provider paths, credentials, scopes or HTTP properties.
	return e.Schema == "kgaga.vault.audit.v1" &&
		e.Action == "sentinel_incident" &&
		incidentHexID(e.AttemptID) && incidentHexID(e.IncidentID) &&
		metadataOK(e.VaultID) && metadataOK(e.AgentID) &&
		metadataOK(e.Owner) && metadataOK(e.Audience) &&
		e.Name == "" && e.Version == 0 && e.Origin == "" &&
		e.Method == "" && e.Target == "" && e.PassportID == "" &&
		e.MCPMethod == "" && e.Tool == "" && e.Provider == "" &&
		e.ProviderVersion == 0 && e.Status == 0 &&
		e.DeliveryID == "" && e.DeliveryPhase == "" && e.DeliveryAttempt == 0 && e.DeliveryChannel == "" &&
		e.IncidentCount >= 1 && e.IncidentCount <= 512 &&
		e.IncidentWindowSeconds >= 1 && e.IncidentWindowSeconds <= 86400
}

// RestoreIncidentManager first verifies the complete journal against the
// independently trusted Head supplied when opening the AnchoredJournal,
// then validates the exact open/acknowledge/resolve sequence for each case.
// Nothing is repaired, truncated, re-signed or acknowledged during recovery.
//
// Must be the only IncidentManager mutating this journal. The in-memory
// index is not a cross-process consensus protocol; use in synthetic tests
// and trusted single-host development only.
func RestoreIncidentManager(j *ledger.AnchoredJournal, max int, clock func() time.Time) (*IncidentManager, error) {
	if j == nil || max < 1 || max > 4096 {
		return nil, ErrIncident
	}
	events, expected, err := j.IncidentHistory(max * 3)
	if err != nil {
		return nil, ErrIncidentHistory
	}
	m, err := NewIncidentManager(j, max, clock)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(events))
	for _, e := range events {
		if !safeIncidentMetadata(e) {
			return nil, ErrIncidentHistory
		}
		if _, exists := seen[e.AttemptID]; exists {
			return nil, ErrIncidentHistory
		}
		seen[e.AttemptID] = struct{}{}
		at, err := replayTime(e.Timestamp)
		if err != nil || (!m.last.IsZero() && at.Before(m.last)) {
			return nil, ErrIncidentHistory
		}
		switch e.Phase {
		case "opened":
			if e.IncidentState != IncidentOpen || e.IncidentRevision != 1 ||
				e.Actor != "sentinel" || e.OperatorID != "" ||
				e.IncidentResolution != "" {
				return nil, ErrIncidentHistory
			}
			alert, err := recoveredAlert(e, at)
			if err != nil {
				return nil, err
			}
			id := e.IncidentID
			if _, exists := m.cases[id]; exists || len(m.cases) >= max {
				return nil, ErrIncidentHistory
			}
			key := incidentSource(alert)
			if m.active[key] != "" {
				return nil, ErrIncidentHistory
			}
			inc := Incident{
				Schema: IncidentSchema, ID: id, State: IncidentOpen,
				Revision: 1, Alert: alert,
				OpenedAt: e.Timestamp, UpdatedAt: e.Timestamp,
			}
			m.cases[id] = inc
			m.active[key] = id
		case "acknowledged", "resolved":
			inc, exists := m.cases[e.IncidentID]
			if !exists || e.IncidentRevision != inc.Revision+1 ||
				e.Actor != "local_operator" || !metadataOK(e.OperatorID) ||
				e.IncidentSignal != inc.Alert.Signal ||
				e.VaultID != inc.Alert.VaultID || e.AgentID != inc.Alert.AgentID ||
				e.Owner != inc.Alert.Owner || e.Audience != inc.Alert.Audience ||
				e.IncidentObservedAt != inc.Alert.ObservedAt ||
				e.IncidentCount != inc.Alert.Count ||
				e.IncidentWindowSeconds != inc.Alert.WindowSeconds {
				return nil, ErrIncidentHistory
			}
			if e.Phase == "acknowledged" {
				if inc.State != IncidentOpen || e.IncidentState != IncidentAcknowledged ||
					e.IncidentResolution != "" {
					return nil, ErrIncidentHistory
				}
				inc.State = IncidentAcknowledged
				inc.AcknowledgedBy = e.OperatorID
			} else {
				if inc.State != IncidentAcknowledged || e.IncidentState != IncidentResolved ||
					(e.IncidentResolution != ResolutionBenign &&
						e.IncidentResolution != ResolutionConfirmed &&
						e.IncidentResolution != ResolutionInconclusive) {
					return nil, ErrIncidentHistory
				}
				inc.State = IncidentResolved
				inc.ResolvedBy = e.OperatorID
				inc.Resolution = e.IncidentResolution
				delete(m.active, incidentSource(inc.Alert))
			}
			inc.Revision = e.IncidentRevision
			inc.UpdatedAt = e.Timestamp
			m.cases[inc.ID] = inc
		default:
			return nil, ErrIncidentHistory
		}
		m.last = at
	}
	observed, err := j.Head()
	if err != nil || observed != expected {
		return nil, ErrIncidentHistory
	}
	return m, nil
}
