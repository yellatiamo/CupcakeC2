package store

import (
    "cupcake-server/internal/model"
)

// User store
func GetUserByUsername(username string) (*model.User, error) {
    var user model.User
    err := DB.Where("username = ?", username).First(&user).Error
    return &user, err
}

func GetAllUsers() ([]model.User, error) {
    var users []model.User
    err := DB.Find(&users).Error
    return users, err
}

func SaveUser(user *model.User) error {
    return DB.Save(user).Error
}

func DeleteUser(id uint) error {
    return DB.Delete(&model.User{}, id).Error
}

func SaveLoginLog(log *model.LoginLog) error {
    return DB.Create(log).Error
}

func GetLoginLogs(limit int) ([]model.LoginLog, error) {
    var logs []model.LoginLog
    err := DB.Order("created_at desc").Limit(limit).Find(&logs).Error
    return logs, err
}

// SaveAuditLog persists an MCP/panel audit entry. Best-effort: never panics;
// returns nil when DB is not initialized (e.g. unit tests without InitDB).
func SaveAuditLog(entry *model.AuditLog) error {
    if DB == nil || entry == nil {
        return nil
    }
    return DB.Create(entry).Error
}

func GetAuditLogs(limit int) ([]model.AuditLog, error) {
    var logs []model.AuditLog
    if DB == nil {
        return logs, nil
    }
    if limit <= 0 {
        limit = 100
    }
    err := DB.Order("created_at desc").Limit(limit).Find(&logs).Error
    return logs, err
}

