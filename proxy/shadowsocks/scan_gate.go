package shadowsocks

import (
	"runtime"
	"time"
)

// fullScanWait is how long a request waits for a full scan slot.
const fullScanWait = 100 * time.Millisecond

// fullScanSlots bounds the full scans that run at once in the process, so
// that requests from many IPs at once cannot use more than half the CPUs.
var fullScanSlots = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)/2))

// acquireFullScan reports whether a full scan slot was taken. A taken slot
// must be given back with releaseFullScan.
func acquireFullScan() bool {
	select {
	case fullScanSlots <- struct{}{}:
		return true
	default:
	}
	timer := time.NewTimer(fullScanWait)
	defer timer.Stop()
	select {
	case fullScanSlots <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

func releaseFullScan() {
	<-fullScanSlots
}
