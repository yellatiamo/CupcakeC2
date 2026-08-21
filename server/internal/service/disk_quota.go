package services

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/disk"
)

// defaultMinFreeDiskMiB is the default reserve kept free after a write (100 MiB).
// Override with env CUPCAKE_MIN_FREE_DISK_MB (integer MiB; 0 disables reserve).
const defaultMinFreeDiskMiB int64 = 100

// MinFreeDiskBytes returns the minimum free-disk reserve that must remain after a write.
// Configurable via CUPCAKE_MIN_FREE_DISK_MB (MiB). Default 100 MiB.
func MinFreeDiskBytes() int64 {
	s := strings.TrimSpace(os.Getenv("CUPCAKE_MIN_FREE_DISK_MB"))
	if s == "" {
		return defaultMinFreeDiskMiB << 20
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return defaultMinFreeDiskMiB << 20
	}
	return n << 20
}

// RejectIfInsufficient is the pure disk-quota gate used by production wrappers and tests.
// Rejects when free < need + minFree (after clamping negatives to 0).
func RejectIfInsufficient(free, need, minFree int64) error {
	if free < 0 {
		free = 0
	}
	if need < 0 {
		need = 0
	}
	if minFree < 0 {
		minFree = 0
	}
	// need + minFree may overflow for pathological inputs; guard by saturating.
	if need > 0 && minFree > (1<<63-1)-need {
		return fmt.Errorf("insufficient disk space: free=%d need=%d min_free=%d", free, need, minFree)
	}
	required := need + minFree
	if free < required {
		return fmt.Errorf("insufficient disk space: free=%d need=%d min_free=%d", free, need, minFree)
	}
	return nil
}

// FreeDiskBytes reports free bytes on the volume containing root.
// Walks up to an existing ancestor if root does not yet exist.
func FreeDiskBytes(root string) (int64, error) {
	path := strings.TrimSpace(root)
	if path == "" {
		path = "."
	}
	for {
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			break
		}
		// Also accept an existing file path (query its volume).
		if _, err := os.Stat(path); err == nil {
			break
		}
		parent := filepath.Dir(path)
		if parent == path {
			path = "."
			break
		}
		path = parent
	}
	usage, err := disk.Usage(path)
	if err != nil {
		return 0, err
	}
	return int64(usage.Free), nil
}

// CheckDiskForWrite queries free space under root and rejects when free < need + MinFreeDiskBytes().
func CheckDiskForWrite(root string, needBytes int64) error {
	free, err := FreeDiskBytes(root)
	if err != nil {
		return fmt.Errorf("disk free space check failed: %w", err)
	}
	return RejectIfInsufficient(free, needBytes, MinFreeDiskBytes())
}
