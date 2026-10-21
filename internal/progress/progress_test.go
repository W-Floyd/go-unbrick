package progress

import "testing"

func TestTask(t *testing.T) {
	task := Begin("unpacking x", 200)
	task.Add(50)
	a := Active()
	if len(a) != 1 || a[0].Percent != 25 || a[0].ETA != -1 {
		t.Fatalf("%+v", a)
	}
	if got := Text(); got != "unpacking x 25%" {
		t.Errorf("text %q", got)
	}
	task.End()
	if len(Active()) != 0 || Text() != "" {
		t.Error("still active")
	}
}
