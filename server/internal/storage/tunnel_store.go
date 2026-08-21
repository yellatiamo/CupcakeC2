package store

import (
	"cupcake-server/internal/model"
)

func SaveTunnel(t *model.Tunnel) error {
	return DB.Save(t).Error
}

func GetAllTunnels() ([]model.Tunnel, error) {
	var tunnels []model.Tunnel
	err := DB.Find(&tunnels).Error
	return tunnels, err
}

func UpdateTunnelStatus(port, status string) error {
	return DB.Model(&model.Tunnel{}).Where("port = ?", port).Update("status", status).Error
}

func DeleteTunnel(port string) error {
	return DB.Where("port = ?", port).Delete(&model.Tunnel{}).Error
}

