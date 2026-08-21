package services

import (
	"cupcake-server/pkg/globals"
	"cupcake-server/pkg/logx"
	"cupcake-server/internal/storage"
	"time"
)

// StartAgentHealthMonitor marks agents stale/offline when LastSeen is too old.
func StartAgentHealthMonitor(staleAfter time.Duration) {
	if staleAfter <= 0 {
		staleAfter = 3 * time.Minute
	}
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			agents, err := store.GetAllAgents()
			if err != nil {
				continue
			}
			for _, a := range agents {
				if a.Status != "online" && a.Status != "memory_online" {
					continue
				}
				// Live connection present → refresh last seen implicitly
				if _, ok := globals.Clients.Load(a.UUID); ok {
					continue
				}
				if now.Sub(a.LastSeen) > staleAfter {
					_ = store.UpdateAgentStatus(a.UUID, "stale")
					logx.Info("agent marked stale", "uuid", a.UUID, "last_seen", a.LastSeen)
				}
			}
		}
	}()
}

