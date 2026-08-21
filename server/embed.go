package server

import "embed"

//go:embed web/dist/*
var WebDist embed.FS
