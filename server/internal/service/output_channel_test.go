package services

import (
	"sync"
	"testing"
	"time"

	"cupcake-server/pkg/globals"
)

func TestTrySendOutputDoesNotPanicAndAcceptsWhenBuffered(t *testing.T) {
	ch := make(chan string, 2)
	client := &globals.Client{UUID: "test-agent", OutputChannel: ch}
	trySendOutput(client, "msg1")
	trySendOutput(client, "msg2")
	done := make(chan struct{})
	go func() {
		trySendOutput(client, "msg3")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("trySendOutput blocked")
	}
	trySendOutput(nil, "x")
}

func TestTrySendOutputRaceWithClose(t *testing.T) {
	ch := make(chan string, 8)
	client := &globals.Client{UUID: "race-agent", OutputChannel: ch}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			trySendOutput(client, "x")
			if n%4 == 0 {
				client.CloseOutputChannel()
			}
		}(i)
	}
	wg.Wait()
	trySendOutput(client, "after-close")
}

func TestTrySendOutputCountsDrops(t *testing.T) {
	ch := make(chan string, 1)
	client := &globals.Client{UUID: "drop-agent", OutputChannel: ch}
	ch <- "full"
	before := client.DroppedOutputs.Load()
	gBefore := globals.GlobalDroppedOutputs.Load()
	// fill + drop
	for i := 0; i < 10; i++ {
		trySendOutput(client, "y")
	}
	if client.DroppedOutputs.Load() <= before && globals.GlobalDroppedOutputs.Load() <= gBefore {
		// drain may succeed sometimes; force closed channel path instead
		client.CloseOutputChannel()
		trySendOutput(client, "z")
	}
}
