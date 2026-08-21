package store

import (
	"cupcake-server/internal/model"
	"time"
)

func SaveAgent(agent *model.Agent) error {
	// Use GORM's Save which handles both Create and Update (Upsert)
	agent.LastSeen = time.Now()
	if agent.CreatedAt.IsZero() {
		agent.CreatedAt = time.Now()
	}
	agent.UpdatedAt = time.Now()

	return DB.Save(agent).Error
}

func GetAgent(uuid string) (*model.Agent, error) {
	var agent model.Agent
	err := DB.Where("uuid = ?", uuid).First(&agent).Error
	if err != nil {
		return nil, err
	}
	return &agent, nil
}

func GetAllAgents() ([]model.Agent, error) {
	var agents []model.Agent
	err := DB.Find(&agents).Error
	return agents, err
}

func UpdateAgentStatus(uuid, status string) error {
	return DB.Model(&model.Agent{}).Where("uuid = ?", uuid).Updates(map[string]interface{}{
		"status":    status,
		"last_seen": time.Now(),
	}).Error
}

func DeleteAgent(uuid string) error {
	return DB.Delete(&model.Agent{}, "uuid = ?", uuid).Error
}

func ResetAllAgentsOffline() error {
	return DB.Model(&model.Agent{}).Where("1 = 1").Update("status", "offline").Error
}

