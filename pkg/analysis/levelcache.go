package analysis

import (
	"strings"
	"sync"
)

// levelCache opens the levels along a path of entry names once each and keeps
// them: what Run.LevelAt and Browser.LevelAt both do, over their own level types.
type levelCache[L any] struct {
	mu     sync.Mutex
	levels map[string]L
}

// at is the level at path from root. step opens the level inside the entry called
// name in cur; it is called once per level, under the cache's lock.
func (c *levelCache[L]) at(root L, path []string, step func(cur L, name string) (L, error)) (L, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.levels == nil {
		c.levels = map[string]L{}
	}
	cur := root
	for i, name := range path {
		key := strings.Join(path[:i+1], "\x00")
		if l, ok := c.levels[key]; ok {
			cur = l
			continue
		}
		l, err := step(cur, name)
		if err != nil {
			var zero L
			return zero, err
		}
		c.levels[key] = l
		cur = l
	}
	return cur, nil
}
