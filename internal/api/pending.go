package api

import "net/http"

// Route groups completed in later milestones (WebAuthn M6, domains M5,
// volumes M3, backups/updates M7).
func (s *Server) webauthnRoutes(pre, a func(handler) http.HandlerFunc) {}
func (s *Server) domainRoutes(a func(handler) http.HandlerFunc)        {}
func (s *Server) volumeRoutes(a func(handler) http.HandlerFunc)        {}
func (s *Server) backupRoutes(a func(handler) http.HandlerFunc)        {}
func (s *Server) updateRoutes(a func(handler) http.HandlerFunc)        {}
