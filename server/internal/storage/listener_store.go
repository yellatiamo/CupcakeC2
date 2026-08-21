package store

import (
	"cupcake-server/internal/model"
)

func SaveListener(l *model.Listener) error {
	return DB.Save(l).Error
}

func GetAllListeners() ([]model.Listener, error) {
	var listeners []model.Listener
	err := DB.Find(&listeners).Error
	return listeners, err
}

func DeleteListener(id string) error {
	return DB.Delete(&model.Listener{}, "id = ?", id).Error
}

func UpdateListenerStatus(id, status string) error {
	return DB.Model(&model.Listener{}).Where("id = ?", id).Update("status", status).Error
}

