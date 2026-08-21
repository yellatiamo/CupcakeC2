package model

import "gorm.io/gorm"

// BindProfile 用于存储正向连接（Bind）的预设凭据配置
type BindProfile struct {
	gorm.Model
	Name           string `json:"name" gorm:"uniqueIndex"` // 分组名称/配置名称
	AesKey         string `json:"aes_key"`                 // 加密密钥
	EncryptionSalt string `json:"encryption_salt"`          // 加密盐值
	ObfuscateMode  string `json:"obfuscate_mode"`          // 混淆模式
}
