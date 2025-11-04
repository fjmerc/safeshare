package static

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web/*
var content embed.FS

// FileSystem returns an http.FileSystem for the embedded static files
func FileSystem() http.FileSystem {
	// Strip the "web" prefix from paths
	fsys, err := fs.Sub(content, "web")
	if err != nil {
		panic(err)
	}
	return http.FS(fsys)
}

// Handler returns an http.Handler that serves the embedded static files
func Handler() http.Handler {
	return http.FileServer(FileSystem())
}
