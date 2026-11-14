package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// byteSize renders a byte count in human-readable units. It replaces the
// fmtutil.Bytes type the pre-rewrite server used.
type byteSize int64

func (b byteSize) String() string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", int64(b))
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// humanDuration renders a rough, human-readable elapsed time.
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return "just now"
	case d < time.Minute:
		return plural(int(d.Seconds()), "second")
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute")
	case d < 24*time.Hour:
		return plural(int(d.Hours()), "hour")
	case d < 365*24*time.Hour:
		return plural(int(d.Hours()/24), "day")
	default:
		return plural(int(d.Hours()/24/365), "year")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s ago", n, unit)
	}
	return fmt.Sprintf("%d %ss ago", n, unit)
}

// File is the view model for a single upload, as consumed by the templates.
type File struct {
	ID       string
	Name     string
	Uploaded time.Time
	Size     byteSize
}

func (f *File) Ext() string { return filepath.Ext(f.Name) }
func (f *File) Ago() string { return humanDuration(time.Since(f.Uploaded)) }

// displayName strips the cache's "<id>." prefix from a stored filename,
// returning the original upload name. Stored names always contain at least the
// separating dot, but guard against malformed entries just in case.
func displayName(stored string) string {
	if i := strings.IndexByte(stored, '.'); i >= 0 {
		return stored[i+1:]
	}
	return stored
}

// getSortedList returns up to limit files starting at offset, newest first.
//
// Unlike the pre-rewrite version it takes a single read lock for the whole
// operation instead of re-locking per entry (the old code called Stat while
// already holding the read lock, which can deadlock a sync.RWMutex if a writer
// arrives in between).
func getSortedList(offset, limit int) []*File {
	ids := fileCache.SortedIDs() // newest-last
	n := len(ids)
	if offset > n {
		offset = 0
	}
	if limit < 0 || limit > n-offset {
		limit = n - offset
	}

	fileCache.RLock()
	defer fileCache.RUnlock()

	list := make([]*File, 0, limit)
	// SortedIDs is ascending by modtime; we want newest first.
	for i := 0; i < limit; i++ {
		id := ids[n-1-offset-i]
		fi := fileCache.FileInfo(id)
		if fi == nil {
			continue
		}
		list = append(list, &File{
			ID:       id,
			Name:     displayName(fi.Name()),
			Uploaded: fi.ModTime(),
			Size:     byteSize(fi.Size()),
		})
	}
	return list
}
