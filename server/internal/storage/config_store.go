package store

import (
    "cupcake-server/internal/model"
)

// Global Settings helpers (key/value store). Users and login audit live in user_store.
func GetSetting(key string) string {
    var setting model.GlobalSetting
    // Use Find instead of First to avoid ErrRecordNotFound noise in logs
    if err := DB.Where("key = ?", key).Limit(1).Find(&setting).Error; err != nil {
        return ""
    }
    return setting.Value
}

func SetSetting(key, value, group string) error {
    setting := model.GlobalSetting{
        Key:   key,
        Value: value,
        Group: group,
    }
    return DB.Save(&setting).Error
}

func GetSettingsByGroup(group string) ([]model.GlobalSetting, error) {
    var settings []model.GlobalSetting
    err := DB.Where("group = ?", group).Find(&settings).Error
    return settings, err
}

// Webhooks
func GetAllWebhooks() ([]model.NotificationWebhook, error) {
    var hooks []model.NotificationWebhook
    err := DB.Find(&hooks).Error
    return hooks, err
}

func SaveWebhook(hook *model.NotificationWebhook) error {
    return DB.Save(hook).Error
}

func DeleteWebhook(id uint) error {
    return DB.Delete(&model.NotificationWebhook{}, id).Error
}

