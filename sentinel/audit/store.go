package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// MemStore is an in-memory Store for tests and dev mode.
type MemStore struct {
	mu   sync.Mutex
	recs []Record
}

func NewMemStore() *MemStore { return &MemStore{} }

func (s *MemStore) Append(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, r)
	return nil
}

func (s *MemStore) Records() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, len(s.recs))
	copy(out, s.recs)
	return out, nil
}

func (s *MemStore) Last() (Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.recs) == 0 {
		return Record{}, false, nil
	}
	return s.recs[len(s.recs)-1], true, nil
}

// FileStore appends records as JSON Lines to a single file. Each line is a
// complete Record; the format is what tools/compliance consumes directly.
type FileStore struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// OpenFileStore opens (creating if needed) a JSONL store at path.
func OpenFileStore(path string) (*FileStore, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open store: %w", err)
	}
	return &FileStore{path: path, f: f}, nil
}

func (s *FileStore) Append(r Record) error {
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(append(line, '\n')); err != nil {
		return err
	}
	// ponytail: Sync per append is the durable-but-slow choice; batch fsync
	// with a flush interval if append throughput ever matters.
	return s.f.Sync()
}

func (s *FileStore) Records() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return readJSONL(s.path)
}

func (s *FileStore) Last() (Record, bool, error) {
	recs, err := s.Records()
	if err != nil || len(recs) == 0 {
		return Record{}, false, err
	}
	return recs[len(recs)-1], true, nil
}

// Close closes the underlying file.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// ReadFile loads all records from a JSONL export, for offline verification.
func ReadFile(path string) ([]Record, error) { return readJSONL(path) }

func readJSONL(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var recs []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		if len(sc.Bytes()) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("audit: %s line %d: %w", path, line, err)
		}
		recs = append(recs, r)
	}
	return recs, sc.Err()
}
