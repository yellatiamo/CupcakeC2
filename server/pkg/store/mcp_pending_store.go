package store

import (
	"time"

	"cupcake-server/pkg/model"
)

// CreateMcpPending inserts a new pending MCP request.
func CreateMcpPending(r *model.McpPendingRequest) error {
	return DB.Create(r).Error
}

// GetMcpPending returns a request by id.
func GetMcpPending(id string) (*model.McpPendingRequest, error) {
	var r model.McpPendingRequest
	if err := DB.Where("id = ?", id).First(&r).Error; err != nil {
		return nil, err
	}
	return &r, nil
}

// ListMcpPending lists requests; empty status returns all (newest first).
// Approve/deny/execute only change status — rows are never deleted here.
func ListMcpPending(status string, limit int) ([]model.McpPendingRequest, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	q := DB.Model(&model.McpPendingRequest{}).Order("created_at DESC").Limit(limit)
	if status != "" {
		q = q.Where("status = ?", status)
	}
	var rows []model.McpPendingRequest
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// CountMcpPending counts by status.
func CountMcpPending(status string) (int64, error) {
	var n int64
	q := DB.Model(&model.McpPendingRequest{})
	if status != "" {
		q = q.Where("status = ?", status)
	}
	err := q.Count(&n).Error
	return n, err
}

// SaveMcpPending updates all fields of a pending request.
func SaveMcpPending(r *model.McpPendingRequest) error {
	return DB.Save(r).Error
}

// ExpireStaleMcpPending marks past-due pending rows as expired. Returns count.
func ExpireStaleMcpPending() (int64, error) {
	now := time.Now()
	res := DB.Model(&model.McpPendingRequest{}).
		Where("status = ? AND expires_at < ?", "pending", now).
		Updates(map[string]interface{}{
			"status":     "expired",
			"error_code": "expired",
			"updated_at": now,
		})
	return res.RowsAffected, res.Error
}
