package store

import (
	"time"

	"cupcake-server/internal/model"
)

// CreateAdTask inserts a new AD task record.
func CreateAdTask(task *model.AdTask) error {
	if task.CreatedAt.IsZero() {
		task.CreatedAt = time.Now()
	}
	if task.UpdatedAt.IsZero() {
		task.UpdatedAt = time.Now()
	}
	if task.Status == "" {
		task.Status = "pending"
	}
	if task.RiskLevel == "" {
		task.RiskLevel = "low"
	}
	return DB.Create(task).Error
}

// UpdateAdTaskStatus updates status and error code for an AD task.
func UpdateAdTaskStatus(reqID, status, errorCode string) error {
	return DB.Model(&model.AdTask{}).Where("req_id = ?", reqID).Updates(map[string]interface{}{
		"status":     status,
		"error_code": errorCode,
		"updated_at": time.Now(),
	}).Error
}

// UpdateAdTaskResult stores the result summary and artifact metadata.
func UpdateAdTaskResult(reqID, summaryJSON, artifactPath, artifactSHA256 string, artifactBytes int64) error {
	return DB.Model(&model.AdTask{}).Where("req_id = ?", reqID).Updates(map[string]interface{}{
		"summary_json":    summaryJSON,
		"artifact_path":   artifactPath,
		"artifact_sha256": artifactSHA256,
		"artifact_bytes":  artifactBytes,
		"status":          "completed",
		"updated_at":      time.Now(),
	}).Error
}

// ListAdTasks returns all AD tasks, newest first.
func ListAdTasks() ([]model.AdTask, error) {
	var tasks []model.AdTask
	err := DB.Order("created_at desc").Find(&tasks).Error
	return tasks, err
}

// ListAdTasksByAgent returns AD tasks for a specific agent, newest first.
func ListAdTasksByAgent(agentUUID string) ([]model.AdTask, error) {
	var tasks []model.AdTask
	err := DB.Where("agent_uuid = ?", agentUUID).Order("created_at desc").Find(&tasks).Error
	return tasks, err
}

// GetAdTaskByReqID returns a single AD task by request ID.
// Uses Find (not First) to avoid GORM emitting "record not found" logs for the
// very common case of "this req_id is not an AD task". Returns (nil, nil) when
// no matching row exists.
func GetAdTaskByReqID(reqID string) (*model.AdTask, error) {
	var tasks []model.AdTask
	if err := DB.Where("req_id = ?", reqID).Limit(1).Find(&tasks).Error; err != nil {
		return nil, err
	}
	if len(tasks) == 0 {
		return nil, nil
	}
	return &tasks[0], nil
}

// GetAdTaskByID returns a single AD task by primary key.
func GetAdTaskByID(id uint) (*model.AdTask, error) {
	var task model.AdTask
	err := DB.First(&task, id).Error
	if err != nil {
		return nil, err
	}
	return &task, nil
}

// DeleteAdTask removes an AD task record.
func DeleteAdTask(id uint) error {
	return DB.Delete(&model.AdTask{}, id).Error
}

// PurgeExpiredAdTasks removes AD tasks older than the given duration.
// Returns count of removed rows.
func PurgeExpiredAdTasks(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	res := DB.Where("created_at < ?", cutoff).Delete(&model.AdTask{})
	return res.RowsAffected, res.Error
}

// CountAdTasks returns total AD task count (for dashboard / metrics).
func CountAdTasks() (int64, error) {
	var count int64
	err := DB.Model(&model.AdTask{}).Count(&count).Error
	return count, err
}
