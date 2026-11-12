package shadowsocks

import (
	"runtime"
	"time"
)

const fullScanWait = 100 * time.Millisecond

var fullScanSlots = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)/2))

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
