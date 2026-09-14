package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Each test starts its own Redis on a Unix socket, with persistence disabled.
// No connection to the application's configured Redis instance is possible.
func testStore(t *testing.T) *Store {
	t.Helper()
	binary, err := exec.LookPath("redis-server")
	if err != nil {
		t.Fatal("redis-server is required for integration tests")
	}
	// Keep below macOS's 104-byte Unix socket path limit.
	socketDir, err := os.MkdirTemp("/tmp", "vtss-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "redis.sock")
	cmd := exec.Command(binary, "--port", "0", "--unixsocket", socket, "--unixsocketperm", "700", "--save", "", "--appendonly", "no")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	store := &Store{rdb: redis.NewClient(&redis.Options{Network: "unix", Addr: socket, MaxRetries: -1})}
	t.Cleanup(func() { _ = store.Close() })
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if store.Ping(context.Background()) == nil {
			return store
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("isolated Redis did not become ready")
	return nil
}
func TestBurnRaceHasExactlyOneWinner(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, "race", "opaque-ciphertext", time.Minute); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var winners atomic.Int32
	start := make(chan struct{})
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			value, err := s.Burn(ctx, "race")
			if err == nil {
				winners.Add(1)
				if value != "opaque-ciphertext" {
					t.Errorf("wrong ciphertext")
				}
			} else if !errors.Is(err, ErrNotFound) {
				t.Errorf("burn: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners=%d", winners.Load())
	}
}
func TestDuplicateSavePreservesOriginal(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, "same", "original", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, "same", "replacement", time.Minute); !errors.Is(err, ErrExists) {
		t.Fatalf("%v", err)
	}
	value, err := s.Burn(ctx, "same")
	if err != nil || value != "original" {
		t.Fatalf("%q %v", value, err)
	}
}
func TestExpirationAndMetadata(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, "expires", "opaque", 150*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TTL(ctx, "expires"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, err := s.TTL(ctx, "expires")
		if errors.Is(err, ErrNotFound) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := s.Burn(ctx, "expires"); !errors.Is(err, ErrNotFound) {
		t.Fatal(fmt.Sprintf("expired burn: %v", err))
	}
}
func TestMetadataDoesNotBurn(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, "meta", "opaque", time.Minute); err != nil {
		t.Fatal(err)
	}
	if ttl, err := s.TTL(ctx, "meta"); err != nil || ttl <= 0 {
		t.Fatalf("ttl=%v err=%v", ttl, err)
	}
	if value, err := s.Burn(ctx, "meta"); err != nil || value != "opaque" {
		t.Fatalf("%q %v", value, err)
	}
	if _, err := s.TTL(ctx, "meta"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
