# 服务端架构文档

## 目录结构

server/
├── cmd/server/
│   └── main.go                 # 服务入口点
│
├── internal/                   # 私有包（不被外部引用）
│   ├── controller/             # HTTP 路由处理层
│   ├── service/                # 业务逻辑层
│   ├── storage/                # 数据持久化层
│   ├── model/                  # 数据模型定义
│   ├── pkg/                    # 内部工具包
│   ├── config/                 # 配置管理
│   └── middleware/             # HTTP 中间件
│
├── pkg/                        # 公共包
│
├── web/                        # 前端资源
├── assets/                     # 二进制资源
├── config/                     # 配置文件
├── scripts/                    # 构建脚本
├── go.mod
├── go.sum
└── Makefile

## 分层说明

### Controller 层
职责：HTTP 路由处理、请求验证、响应格式化

### Service 层
职责：核心业务逻辑、流程编排

### Storage 层
职责：数据持久化、CRUD 操作

### Model 层
职责：数据结构定义

## 导入规则

- controller → service, model, middleware
- service → storage, model, pkg
- storage → model
- pkg → 标准库和第三方库，不导入 internal

