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

//go:embed templates/*
var templates embed.FS

// Templates returns the server-rendered page templates. They live outside
// web/ on purpose: web/ is served verbatim and its files are hashed for
// each release (scripts/web-asset-hashes.sh), and these pages differ on
// every request.
func Templates() fs.FS {
	fsys, err := fs.Sub(templates, "templates")
	if err != nil {
		panic(err)
	}
	return fsys
}
