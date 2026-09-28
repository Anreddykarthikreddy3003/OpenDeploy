package api

import "net/http"

// Route groups completed in a later milestone (backups/updates M7).
func (s *Server) backupRoutes(a func(handler) http.HandlerFunc) {}
func (s *Server) updateRoutes(a func(handler) http.HandlerFunc) {}
