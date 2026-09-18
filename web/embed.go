// Package web embeds the self-contained administrator interface.
package web

import "embed"

// Assets contains the administrator application and its local assets.
//
//go:embed static/*
var Assets embed.FS
