// Package progress tracks long-running work (unpacking a solid archive, reading
// member heads) so a front end that is waiting can say how far it has got and
// how long is left, without the worker knowing who is watching.
package progress

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Task is one piece of work in flight.
type Task struct {
	label string
	total int64 // 0 when not countable
	done  atomic.Int64
	start time.Time
}

var (
	mu     sync.Mutex
	active = map[*Task]struct{}{}
)

// Begin registers work of total units (0 if unknown). Call End when finished.
func Begin(label string, total int64) *Task {
	t := &Task{label: label, total: total, start: time.Now()}
	mu.Lock()
	active[t] = struct{}{}
	mu.Unlock()
	return t
}

// Add counts n units done.
func (t *Task) Add(n int64) { t.done.Add(n) }

// Reset starts the count again, for work that began over.
func (t *Task) Reset() { t.done.Store(0) }

// End removes the task.
func (t *Task) End() {
	mu.Lock()
	delete(active, t)
	mu.Unlock()
}

// Snapshot is a task as it stands.
type Snapshot struct {
	Label   string  `json:"label"`
	Done    int64   `json:"done"`
	Total   int64   `json:"total"`
	Percent int     `json:"percent"`    // -1 when the total is unknown
	Elapsed float64 `json:"elapsed"`    // seconds
	ETA     float64 `json:"eta"`        // seconds left; -1 when it cannot be estimated yet
	Started int64   `json:"started_ns"` // orders tasks
}

// Active lists the tasks in flight, oldest first.
func Active() []Snapshot {
	mu.Lock()
	ts := make([]*Task, 0, len(active))
	for t := range active {
		ts = append(ts, t)
	}
	mu.Unlock()
	out := make([]Snapshot, 0, len(ts))
	for _, t := range ts {
		d, el := t.done.Load(), time.Since(t.start)
		s := Snapshot{Label: t.label, Done: d, Total: t.total, Percent: -1, ETA: -1, Elapsed: el.Seconds(), Started: t.start.UnixNano()}
		if t.total > 0 {
			s.Percent = int(min(100, 100*d/t.total))
			// Too early a rate is noise: wait for a little progress and time.
			if d > 0 && el > time.Second && d < t.total {
				s.ETA = el.Seconds() * float64(t.total-d) / float64(d)
			}
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started < out[j].Started })
	return out
}

// Text is the newest task as one line ("unpacking x.7z 45% · 12s left"), or ""
// when nothing is running.
func Text() string {
	a := Active()
	if len(a) == 0 {
		return ""
	}
	return a[len(a)-1].String()
}

func (s Snapshot) String() string {
	out := s.Label
	if s.Percent >= 0 {
		out += fmt.Sprintf(" %d%%", s.Percent)
	}
	if s.ETA >= 0 {
		out += " · " + (time.Duration(s.ETA+0.5) * time.Second).String() + " left"
	}
	return out
}
