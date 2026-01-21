package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"passkeyexample/auth"
	"passkeyexample/storage"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	jwtSecret   = "your-secret-key-change-in-production"
	jwtDuration = 24 * time.Hour
	cookieName  = "auth_token"
)

// Server holds all dependencies
type Server struct {
	webAuthn   *webauthn.WebAuthn
	store      *storage.Store
	jwt        *auth.JWTManager
	sessions   map[string]*webauthn.SessionData
	sessionsMu sync.RWMutex
}

func main() {
	// Initialize WebAuthn
	wa, err := auth.NewWebAuthn(auth.Config{
		RPDisplayName: "Passkey Example",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	})
	if err != nil {
		log.Fatalf("Failed to create WebAuthn: %v", err)
	}

	// Initialize user store
	store, err := storage.NewStore("users.json")
	if err != nil {
		log.Fatalf("Failed to create store: %v", err)
	}

	// Initialize JWT manager
	jwtManager := auth.NewJWTManager(jwtSecret, jwtDuration)

	server := &Server{
		webAuthn: wa,
		store:    store,
		jwt:      jwtManager,
		sessions: make(map[string]*webauthn.SessionData),
	}

	// Setup routes
	mux := http.NewServeMux()

	// Static files
	mux.Handle("/", http.FileServer(http.Dir("static")))

	// API routes
	mux.HandleFunc("POST /api/register/begin", server.handleRegisterBegin)
	mux.HandleFunc("POST /api/register/finish", server.handleRegisterFinish)
	mux.HandleFunc("POST /api/login/begin", server.handleLoginBegin)
	mux.HandleFunc("POST /api/login/finish", server.handleLoginFinish)
	mux.HandleFunc("GET /api/user", server.handleGetUser)
	mux.HandleFunc("POST /api/logout", server.handleLogout)
	mux.HandleFunc("POST /api/passkey/add/begin", server.handleAddPasskeyBegin)
	mux.HandleFunc("POST /api/passkey/add/finish", server.handleAddPasskeyFinish)
	mux.HandleFunc("GET /api/passkeys", server.handleListPasskeys)
	mux.HandleFunc("DELETE /api/passkey", server.handleDeletePasskey)
	mux.HandleFunc("PUT /api/passkey", server.handleRenamePasskey)

	log.Println("Server starting on http://localhost:8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// generateSessionID creates a random session ID
func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// handleRegisterBegin starts the registration ceremony
func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	// Check if user already exists
	if _, err := s.store.GetUser(req.Username); err == nil {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Generate user ID
	userID := make([]byte, 32)
	rand.Read(userID)

	// Create temporary user for registration
	user, err := s.store.CreateUser(req.Username, userID)
	if err != nil {
		if err == storage.ErrUserExists {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Begin registration
	options, session, err := s.webAuthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, "Failed to begin registration", http.StatusInternalServerError)
		return
	}

	// Store session
	sessionID := generateSessionID()
	s.sessionsMu.Lock()
	s.sessions[sessionID] = session
	s.sessionsMu.Unlock()

	// Return options with session ID
	response := struct {
		Options   *protocol.CredentialCreation `json:"options"`
		SessionID string                       `json:"sessionId"`
	}{
		Options:   options,
		SessionID: sessionID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRegisterFinish completes the registration ceremony
func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	// Parse the username and session from query
	username := r.URL.Query().Get("username")
	sessionID := r.URL.Query().Get("sessionId")

	if username == "" || sessionID == "" {
		http.Error(w, "Missing username or session ID", http.StatusBadRequest)
		return
	}

	// Get user
	user, err := s.store.GetUser(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Get session
	s.sessionsMu.RLock()
	session, ok := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}

	// Complete registration
	credential, err := s.webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		log.Printf("FinishRegistration error: %v", err)
		http.Error(w, "Failed to finish registration", http.StatusBadRequest)
		return
	}

	// Save credential
	user.AddCredential("Initial Passkey", *credential)
	if err := s.store.UpdateUser(user); err != nil {
		http.Error(w, "Failed to save credential", http.StatusInternalServerError)
		return
	}

	// Clean up session
	s.sessionsMu.Lock()
	delete(s.sessions, sessionID)
	s.sessionsMu.Unlock()

	// Generate JWT token
	token, err := s.jwt.Generate(base64.URLEncoding.EncodeToString(user.ID), user.Name)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(jwtDuration.Seconds()),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleLoginBegin starts the login ceremony
func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	// Get user
	user, err := s.store.GetUser(req.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Begin login
	options, session, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		http.Error(w, "Failed to begin login", http.StatusInternalServerError)
		return
	}

	// Store session
	sessionID := generateSessionID()
	s.sessionsMu.Lock()
	s.sessions[sessionID] = session
	s.sessionsMu.Unlock()

	// Return options with session ID
	response := struct {
		Options   *protocol.CredentialAssertion `json:"options"`
		SessionID string                        `json:"sessionId"`
	}{
		Options:   options,
		SessionID: sessionID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleLoginFinish completes the login ceremony
func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	sessionID := r.URL.Query().Get("sessionId")

	if username == "" || sessionID == "" {
		http.Error(w, "Missing username or session ID", http.StatusBadRequest)
		return
	}

	// Get user
	user, err := s.store.GetUser(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Get session
	s.sessionsMu.RLock()
	session, ok := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}

	// Complete login
	_, err = s.webAuthn.FinishLogin(user, *session, r)
	if err != nil {
		log.Printf("FinishLogin error: %v", err)
		http.Error(w, "Failed to finish login", http.StatusUnauthorized)
		return
	}

	// Clean up session
	s.sessionsMu.Lock()
	delete(s.sessions, sessionID)
	s.sessionsMu.Unlock()

	// Generate JWT token
	token, err := s.jwt.Generate(base64.URLEncoding.EncodeToString(user.ID), user.Name)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(jwtDuration.Seconds()),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleGetUser returns current user info (protected)
func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, err := s.jwt.Validate(cookie.Value)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := s.store.GetUser(claims.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	response := struct {
		Username        string              `json:"username"`
		CredentialCount int                 `json:"credentialCount"`
		UserID          string              `json:"userId"`
		Passkeys        []map[string]string `json:"passkeys"`
	}{
		Username:        user.Name,
		CredentialCount: len(user.Passkeys),
		UserID:          base64.URLEncoding.EncodeToString(user.ID),
		Passkeys:        user.GetPasskeyList(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleLogout clears the auth cookie
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleAddPasskeyBegin starts adding a new passkey for an authenticated user
func (s *Server) handleAddPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	// Verify authentication
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, err := s.jwt.Validate(cookie.Value)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user
	user, err := s.store.GetUser(claims.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Begin registration for new passkey
	options, session, err := s.webAuthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, "Failed to begin registration", http.StatusInternalServerError)
		return
	}

	// Store session
	sessionID := generateSessionID()
	s.sessionsMu.Lock()
	s.sessions[sessionID] = session
	s.sessionsMu.Unlock()

	// Return options with session ID
	response := struct {
		Options   *protocol.CredentialCreation `json:"options"`
		SessionID string                       `json:"sessionId"`
	}{
		Options:   options,
		SessionID: sessionID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAddPasskeyFinish completes adding a new passkey for an authenticated user
func (s *Server) handleAddPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	// Verify authentication
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, err := s.jwt.Validate(cookie.Value)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	sessionID := r.URL.Query().Get("sessionId")
	if sessionID == "" {
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	// Get user
	user, err := s.store.GetUser(claims.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Get session
	s.sessionsMu.RLock()
	session, ok := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	if !ok {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}

	// Get passkey name from query
	passkeyName := r.URL.Query().Get("name")
	if passkeyName == "" {
		passkeyName = "Passkey"
	}

	// Complete registration
	credential, err := s.webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		log.Printf("FinishRegistration error: %v", err)
		http.Error(w, "Failed to finish registration", http.StatusBadRequest)
		return
	}

	// Save credential with name
	user.AddCredential(passkeyName, *credential)
	if err := s.store.UpdateUser(user); err != nil {
		http.Error(w, "Failed to save credential", http.StatusInternalServerError)
		return
	}

	// Clean up session
	s.sessionsMu.Lock()
	delete(s.sessions, sessionID)
	s.sessionsMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "ok",
		"credentialCount": len(user.Passkeys),
	})
}

// handleListPasskeys returns the list of passkeys for the authenticated user
func (s *Server) handleListPasskeys(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, err := s.jwt.Validate(cookie.Value)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := s.store.GetUser(claims.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"passkeys": user.GetPasskeyList(),
	})
}

// handleDeletePasskey removes a passkey (cannot remove the last one)
func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, err := s.jwt.Validate(cookie.Value)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	passkeyID := r.URL.Query().Get("id")
	if passkeyID == "" {
		http.Error(w, "Missing passkey ID", http.StatusBadRequest)
		return
	}

	user, err := s.store.GetUser(claims.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := user.RemoveCredential(passkeyID); err != nil {
		if err == storage.ErrLastCredential {
			http.Error(w, "Cannot remove last passkey", http.StatusBadRequest)
			return
		}
		http.Error(w, "Passkey not found", http.StatusNotFound)
		return
	}

	if err := s.store.UpdateUser(user); err != nil {
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"passkeys": user.GetPasskeyList(),
	})
}

// handleRenamePasskey renames a passkey
func (s *Server) handleRenamePasskey(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, err := s.jwt.Validate(cookie.Value)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.ID == "" || req.Name == "" {
		http.Error(w, "Missing ID or name", http.StatusBadRequest)
		return
	}

	user, err := s.store.GetUser(claims.Username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if err := user.RenameCredential(req.ID, req.Name); err != nil {
		http.Error(w, "Passkey not found", http.StatusNotFound)
		return
	}

	if err := s.store.UpdateUser(user); err != nil {
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"passkeys": user.GetPasskeyList(),
	})
}
