package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	Version     = "1.0.0"
	BuildDate   = "2025-06-13"
	UserAgent   = "BitwardenEventForwarder/1.0.0"
	DefaultPort = "514"
)

// Configuration holds all application configuration
type Configuration struct {
	APIBaseURL      string `json:"api_base_url"`
	IdentityURL     string `json:"identity_url"`
	ClientID        string `json:"client_id"`
	ClientSecret    string `json:"client_secret"`
	SyslogProtocol  string `json:"syslog_protocol"`
	SyslogServer    string `json:"syslog_server"`
	SyslogPort      string `json:"syslog_port"`
	FetchInterval   int    `json:"fetch_interval"`
	LogLevel        string `json:"log_level"`
	MaxMsgSize      int    `json:"max_msg_size"`
	MaxPagination   int    `json:"max_pagination"`
	LogFile         string `json:"log_file"`
	ConnTimeout     int    `json:"conn_timeout"`
	MarkerFile      string `json:"marker_file"`
	FieldMapFile    string `json:"field_map_file"`
	EventMapFile    string `json:"event_map_file"`
}

// OAuth2Token represents an OAuth2 access token
type OAuth2Token struct {
	AccessToken string    `json:"access_token"`
	ExpiresIn   int       `json:"expires_in"`
	TokenType   string    `json:"token_type"`
	Expiry      time.Time `json:"-"`
}

// Event represents a Bitwarden event log entry
type Event struct {
	ID            string                 `json:"id"`
	MemberID      string                 `json:"memberId"`
	ActingUserID  string                 `json:"actingUserId"`
	Type          int                    `json:"type"`
	Date          string                 `json:"date"`
	ItemID        string                 `json:"itemId"`
	CollectionID  string                 `json:"collectionId"`
	GroupID       string                 `json:"groupId"`
	PolicyID      string                 `json:"policyId"`
	Device        int                    `json:"device"`
	IPAddress     string                 `json:"ipAddress"`
	Details       map[string]interface{} `json:"-"`
}

// EventsResponse represents the API response for events
type EventsResponse struct {
	Object            string  `json:"object"`
	Data              []Event `json:"data"`
	ContinuationToken string  `json:"continuationToken"`
}

// LookupRule defines how to perform lookups and map response fields
type LookupRule struct {
	Endpoint        string            `json:"endpoint"`
	ResponseMapping map[string]string `json:"response_mapping"`
}

// FieldMapping defines how to map and enrich event fields
type FieldMapping struct {
	OrderedFields          []string                    `json:"ordered_fields"`
	FieldMappings          map[string]string          `json:"field_mappings"`
	Lookups                map[string]LookupRule      `json:"lookups"`
	CacheInvalidationRules map[int][]string           `json:"cache_invalidation_rules"`
	CEFVendor              string                     `json:"cef_vendor"`
	CEFProduct             string                     `json:"cef_product"`
	CEFVersion             string                     `json:"cef_version"`
}

// LookupCache provides thread-safe caching for API lookups
type LookupCache struct {
	mu    sync.RWMutex
	cache map[string]map[string]interface{}
}

// NewLookupCache creates a new lookup cache
func NewLookupCache() *LookupCache {
	return &LookupCache{
		cache: make(map[string]map[string]interface{}),
	}
}

// Get retrieves a cached value
func (lc *LookupCache) Get(cacheKey, id string) (map[string]interface{}, bool) {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	
	typeCache, ok := lc.cache[cacheKey]
	if !ok {
		return nil, false
	}
	
	data, ok := typeCache[id]
	if !ok {
		return nil, false
	}
	
	return data, true
}

// Set stores a value in the cache
func (lc *LookupCache) Set(cacheKey, id string, data map[string]interface{}) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	
	if lc.cache[cacheKey] == nil {
		lc.cache[cacheKey] = make(map[string]interface{})
	}
	lc.cache[cacheKey][id] = data
}

func main() {
	cfg := loadConfig()

	if err := setupLogging(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to setup logging: %v\n", err)
		os.Exit(1)
	}

	log.Printf("🚀 Starting Bitwarden Event Forwarder v%s", Version)
	log.Printf("📋 Configuration loaded successfully")
	log.Printf("🔗 API Base URL: %s", cfg.APIBaseURL)
	log.Printf("📡 Syslog: %s://%s:%s", cfg.SyslogProtocol, cfg.SyslogServer, cfg.SyslogPort)
	log.Printf("⏱️  Fetch Interval: %d seconds", cfg.FetchInterval)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		log.Printf("🛑 Received shutdown signal (%s), exiting gracefully...", sig)
		cancel()
		os.Exit(0)
	}()

	// Initialize OAuth2 token
	log.Printf("🔐 Authenticating with Bitwarden API...")
	token, err := fetchOAuth2TokenWithRetry(cfg, 3)
	if err != nil {
		log.Fatalf("❌ Authentication failed: %v", err)
	}
	log.Printf("✅ Successfully authenticated (expires: %s)", token.Expiry.Format("2006-01-02 15:04:05"))

	// Initialize components
	cache := NewLookupCache()
	fieldMapping := loadFieldMapping(cfg.FieldMapFile)
	eventTypeNames := loadEventTypeNames(cfg.EventMapFile)

	log.Printf("💾 Cache initialized")
	log.Printf("🗺️  Field mappings loaded (%d lookups)", len(fieldMapping.Lookups))
	log.Printf("📝 Event types loaded (%d types)", len(eventTypeNames))

	// Test syslog connectivity
	if err := testSyslogConnection(cfg); err != nil {
		log.Fatalf("❌ Syslog test failed: %v", err)
	}
	log.Printf("✅ Syslog connectivity verified")

	// Start event polling
	log.Printf("🎯 Starting event polling...")
	pollEventsWithErrorRecovery(ctx, cfg, &token, cache, fieldMapping, eventTypeNames)
}

// loadConfig loads configuration from flags, environment, and files
func loadConfig() Configuration {
	var (
		showHelp     = flag.Bool("help", false, "Show help message")
		showVersion  = flag.Bool("version", false, "Show version information")
		configFile   = flag.String("config", getEnvOrDefault("BW_CONFIG_FILE", ""), "Configuration file path")
		validateOnly = flag.Bool("validate", false, "Validate configuration and exit")
		testMode     = flag.Bool("test", false, "Test connections and exit")
	)

	// Define all configuration flags
	cfg := Configuration{
		APIBaseURL:     *flag.String("api-url", getEnvOrDefault("BW_API_URL", "https://api.bitwarden.com"), "Bitwarden API base URL"),
		IdentityURL:    *flag.String("identity-url", getEnvOrDefault("BW_IDENTITY_URL", "https://identity.bitwarden.com"), "Bitwarden Identity URL"),
		ClientID:       *flag.String("client-id", getEnvOrDefault("BW_CLIENT_ID", ""), "Bitwarden API Client ID"),
		ClientSecret:   *flag.String("client-secret", getEnvOrDefault("BW_CLIENT_SECRET", ""), "Bitwarden API Client Secret"),
		SyslogProtocol: *flag.String("syslog-proto", getEnvOrDefault("SYSLOG_PROTOCOL", "tcp"), "Syslog protocol (tcp/udp)"),
		SyslogServer:   *flag.String("syslog-server", getEnvOrDefault("SYSLOG_SERVER", "localhost"), "Syslog server address"),
		SyslogPort:     *flag.String("syslog-port", getEnvOrDefault("SYSLOG_PORT", DefaultPort), "Syslog server port"),
		FetchInterval:  *flag.Int("interval", getEnvOrIntDefault("FETCH_INTERVAL", 60), "Event fetch interval in seconds"),
		LogLevel:       *flag.String("log-level", getEnvOrDefault("LOG_LEVEL", "info"), "Log level"),
		MaxMsgSize:     *flag.Int("max-msg-size", getEnvOrIntDefault("MAX_MSG_SIZE", 8192), "Maximum syslog message size"),
		MaxPagination:  *flag.Int("max-pagination", getEnvOrIntDefault("MAX_PAGINATION", 50), "Maximum pagination requests"),
		LogFile:        *flag.String("log-file", getEnvOrDefault("LOG_FILE", ""), "Log file path"),
		ConnTimeout:    *flag.Int("conn-timeout", getEnvOrIntDefault("CONNECTION_TIMEOUT", 30), "Connection timeout in seconds"),
		MarkerFile:     *flag.String("marker-file", getEnvOrDefault("MARKER_FILE", "./bitwarden_marker.txt"), "Marker file path"),
		FieldMapFile:   *flag.String("field-map", getEnvOrDefault("FIELD_MAP_FILE", "./bitwarden_field_map.json"), "Field mapping file"),
		EventMapFile:   *flag.String("event-map", getEnvOrDefault("EVENT_MAP_FILE", "./bitwarden_event_map.json"), "Event mapping file"),
	}

	flag.Parse()

	if *showHelp {
		showHelpMessage()
		os.Exit(0)
	}

	if *showVersion {
		showVersionInfo()
		os.Exit(0)
	}

	// Load config file if specified
	if *configFile != "" {
		if err := loadConfigFromFile(&cfg, *configFile); err != nil {
			log.Fatalf("Failed to load config file: %v", err)
		}
	}

	// Validate configuration
	if err := validateConfiguration(cfg); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	if *validateOnly {
		fmt.Println("✅ Configuration validation passed")
		os.Exit(0)
	}

	if *testMode {
		if err := testConnections(cfg); err != nil {
			log.Fatalf("Connection test failed: %v", err)
		}
		fmt.Println("✅ All connection tests passed")
		os.Exit(0)
	}

	return cfg
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvOrIntDefault returns environment variable as int or default
func getEnvOrIntDefault(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		var result int
		if n, err := fmt.Sscanf(value, "%d", &result); err == nil && n == 1 {
			return result
		}
	}
	return defaultValue
}

// setupLogging configures logging output
func setupLogging(cfg Configuration) error {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if cfg.LogFile == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(cfg.LogFile), 0755); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}

	file, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	log.SetOutput(io.MultiWriter(os.Stdout, file))
	return nil
}

// fetchOAuth2Token gets an OAuth2 token from Bitwarden
func fetchOAuth2Token(cfg Configuration) (OAuth2Token, error) {
	form := fmt.Sprintf("grant_type=client_credentials&scope=api.organization&client_id=%s&client_secret=%s",
		cfg.ClientID, cfg.ClientSecret)

	req, err := http.NewRequest(http.MethodPost, cfg.IdentityURL+"/connect/token", strings.NewReader(form))
	if err != nil {
		return OAuth2Token{}, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", UserAgent)

	client := &http.Client{Timeout: time.Duration(cfg.ConnTimeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return OAuth2Token{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return OAuth2Token{}, fmt.Errorf("token request failed (status %d): %s", resp.StatusCode, body)
	}

	var token OAuth2Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return OAuth2Token{}, fmt.Errorf("decode token: %w", err)
	}

	token.Expiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	return token, nil
}

// fetchOAuth2TokenWithRetry attempts token fetch with retries
func fetchOAuth2TokenWithRetry(cfg Configuration, maxRetries int) (OAuth2Token, error) {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(attempt*2) * time.Second
			log.Printf("⏳ Retrying authentication in %v...", backoff)
			time.Sleep(backoff)
		}

		log.Printf("🔄 Authentication attempt %d/%d", attempt, maxRetries)
		token, err := fetchOAuth2Token(cfg)
		if err == nil {
			return token, nil
		}

		lastErr = err
		log.Printf("⚠️  Authentication attempt %d failed: %v", attempt, err)
	}

	return OAuth2Token{}, fmt.Errorf("authentication failed after %d attempts: %w", maxRetries, lastErr)
}

// loadFieldMapping loads field mapping configuration
func loadFieldMapping(filename string) FieldMapping {
	defaultMapping := FieldMapping{
		OrderedFields: []string{
			"rt", "cs1", "cs2", "suser", "email", "status", "2fa", "host_ip",
			"device", "groupId", "collectionId", "policyId", "actingUserId",
			"objectname", "community", "roles", "caseName", "hasDataChanges",
			"changeType", "changeCount", "changedFields", "oldValues", "newValues",
		},
		FieldMappings: map[string]string{
			"date":              "rt",
			"type":              "cs1",
			"id":                "cs2",
			"memberId":          "suser",
			"actingUserId":      "actingUserId",
			"email":             "email",
			"status":            "status",
			"twoFactorEnabled":  "2fa",
			"ipAddress":         "host_ip",
			"device":            "device",
			"groupId":           "groupId",
			"collectionId":      "collectionId",
			"policyId":          "policyId",
			"object":            "objectname",
		},
		Lookups: map[string]LookupRule{
			"memberId": {
				Endpoint: "/public/members/{id}",
				ResponseMapping: map[string]string{
					"name":             "memberName",
					"email":            "memberEmail",
					"status":           "memberStatus",
					"twoFactorEnabled": "member2FA",
				},
			},
			"groupId": {
				Endpoint: "/public/groups/{id}",
				ResponseMapping: map[string]string{
					"name": "groupName",
				},
			},
			"collectionId": {
				Endpoint: "/public/collections/{id}",
				ResponseMapping: map[string]string{
					"name": "collectionName",
				},
			},
			"policyId": {
				Endpoint: "/public/policies/{type}",
				ResponseMapping: map[string]string{
					"type":           "policyType",
					"enabled":        "policyEnabled",
					"policyTypeName": "policyTypeName",
				},
			},
		},
		CacheInvalidationRules: map[int][]string{
			1700: {"policyId"},
			1500: {"memberId"}, 1501: {"memberId"}, 1502: {"memberId"},
			1503: {"memberId"}, 1515: {"memberId"}, 1516: {"memberId"},
			1400: {"groupId"}, 1401: {"groupId"}, 1402: {"groupId"},
			1300: {"collectionId"}, 1301: {"collectionId"}, 1302: {"collectionId"},
		},
		CEFVendor:  "Bitwarden",
		CEFProduct: "Events",
		CEFVersion: "1.0",
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Creating default field mapping file: %s", filename)
			createDefaultConfigFile(filename, defaultMapping)
		}
		return defaultMapping
	}

	var mapping FieldMapping
	if err := json.Unmarshal(data, &mapping); err != nil {
		log.Printf("Error parsing field mapping file: %v, using defaults", err)
		return defaultMapping
	}

	return mapping
}

// createDefaultConfigFile creates a default configuration file
func createDefaultConfigFile(filename string, mapping FieldMapping) {
	if jsonData, err := json.MarshalIndent(mapping, "", "  "); err == nil {
		if err := os.MkdirAll(filepath.Dir(filename), 0755); err == nil {
			ioutil.WriteFile(filename, jsonData, 0644)
		}
	}
}

// loadEventTypeNames loads event type name mappings
func loadEventTypeNames(filename string) map[string]string {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("Failed to read event type map file: %v", err)
		return make(map[string]string)
	}

	var eventMap map[string]string
	if err := json.Unmarshal(data, &eventMap); err != nil {
		log.Printf("Failed to parse event type map JSON: %v", err)
		return make(map[string]string)
	}

	return eventMap
}

// loadMarkerFromFile loads the last processed event marker
func loadMarkerFromFile(filename string) string {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// saveMarkerToFile saves the last processed event marker
func saveMarkerToFile(filename, marker string) error {
	if marker == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("create marker directory: %w", err)
	}

	return ioutil.WriteFile(filename, []byte(marker), 0644)
}

// pollEventsWithErrorRecovery polls events with comprehensive error handling
func pollEventsWithErrorRecovery(ctx context.Context, cfg Configuration, token *OAuth2Token, cache *LookupCache, fieldMapping FieldMapping, eventTypeNames map[string]string) {
	marker := loadMarkerFromFile(cfg.MarkerFile)
	var continuationToken string
	skipUntilMarker := marker != ""
	var lastProcessedID string
	consecutiveErrors := 0
	const maxConsecutiveErrors = 5

	for {
		select {
		case <-ctx.Done():
			log.Printf("Context cancelled, stopping event polling")
			return
		default:
		}

		// Check token expiry
		if time.Now().After(token.Expiry.Add(-time.Minute)) {
			log.Printf("🔄 Refreshing OAuth2 token...")
			newToken, err := fetchOAuth2TokenWithRetry(cfg, 3)
			if err != nil {
				log.Printf("❌ Token refresh failed: %v", err)
				consecutiveErrors++
				if consecutiveErrors >= maxConsecutiveErrors {
					log.Fatalf("💀 Too many consecutive token failures (%d)", consecutiveErrors)
				}
				time.Sleep(time.Duration(cfg.FetchInterval) * time.Second)
				continue
			}
			*token = newToken
			log.Printf("✅ Token refreshed successfully")
			consecutiveErrors = 0
		}

		// Fetch events
		eventsResp, err := fetchEvents(cfg, token, continuationToken)
		if err != nil {
			log.Printf("❌ Event fetch failed: %v", err)
			consecutiveErrors++

			if consecutiveErrors >= maxConsecutiveErrors {
				log.Fatalf("💀 Too many consecutive API failures (%d)", consecutiveErrors)
			}

			backoff := time.Duration(consecutiveErrors*10) * time.Second
			log.Printf("⏳ Backing off for %v...", backoff)
			time.Sleep(backoff)
			continue
		}

		if consecutiveErrors > 0 {
			log.Printf("✅ Recovered from errors")
			consecutiveErrors = 0
		}

		// Process events
		eventsProcessed := 0
		for i := range eventsResp.Data {
			event := &eventsResp.Data[i]

			if skipUntilMarker {
				if event.ID == marker {
					skipUntilMarker = false
					log.Printf("📍 Reached marker %s, resuming", marker)
				}
				continue
			}

			// Enrich and send event
			if err := processEvent(cfg, token, cache, fieldMapping, eventTypeNames, event); err != nil {
				log.Printf("⚠️  Failed to process event %s: %v", event.ID, err)
				continue
			}

			lastProcessedID = event.ID
			eventsProcessed++
		}

		// Save progress
		if lastProcessedID != "" {
			if err := saveMarkerToFile(cfg.MarkerFile, lastProcessedID); err != nil {
				log.Printf("⚠️  Failed to save marker: %v", err)
			}
		}

		if eventsProcessed > 0 {
			log.Printf("✅ Processed %d events", eventsProcessed)
		}

		// Handle pagination
		if eventsResp.ContinuationToken == "" {
			continuationToken = ""
			time.Sleep(time.Duration(cfg.FetchInterval) * time.Second)
		} else {
			continuationToken = eventsResp.ContinuationToken
		}
	}
}

// fetchEvents retrieves events from the Bitwarden API
func fetchEvents(cfg Configuration, token *OAuth2Token, continuationToken string) (EventsResponse, error) {
	url := cfg.APIBaseURL + "/public/events"
	if continuationToken != "" {
		url += "?continuationToken=" + continuationToken
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return EventsResponse{}, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("User-Agent", UserAgent)

	client := &http.Client{Timeout: time.Duration(cfg.ConnTimeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return EventsResponse{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return EventsResponse{}, fmt.Errorf("API returned status %d: %s", resp.StatusCode, body)
	}

	var eventsResp EventsResponse
	if err := json.NewDecoder(resp.Body).Decode(&eventsResp); err != nil {
		return EventsResponse{}, fmt.Errorf("decode response: %w", err)
	}

	return eventsResp, nil
}

// processEvent enriches and sends a single event
func processEvent(cfg Configuration, token *OAuth2Token, cache *LookupCache, fieldMapping FieldMapping, eventTypeNames map[string]string, event *Event) error {
	// Enrich event
	enrichEventWithLookups(cfg, token, cache, fieldMapping, event)

	// Format as CEF
	cef := formatEventAsCEF(*event, fieldMapping, eventTypeNames)

	// Send to syslog with retry
	return sendToSyslogWithRetry(cfg, cef, 3)
}

// enrichEventWithLookups enriches an event with API lookup data
func enrichEventWithLookups(cfg Configuration, token *OAuth2Token, cache *LookupCache, mapping FieldMapping, event *Event) {
	eventData := map[string]interface{}{
		"id":            event.ID,
		"memberId":      event.MemberID,
		"actingUserId":  event.ActingUserID,
		"type":          event.Type,
		"date":          event.Date,
		"itemId":        event.ItemID,
		"collectionId":  event.CollectionID,
		"groupId":       event.GroupID,
		"policyId":      event.PolicyID,
		"device":        event.Device,
		"ipAddress":     event.IPAddress,
	}

	if event.Details == nil {
		event.Details = make(map[string]interface{})
	}

	// Copy event data to details
	for key, value := range eventData {
		if value != nil && value != "" && value != 0 {
			event.Details[key] = value
		}
	}

	// Smart cache invalidation
	invalidateCacheForEvent(cache, mapping, event)

	// Perform lookups
	for fieldName, rule := range mapping.Lookups {
		fieldValue, ok := eventData[fieldName].(string)
		if !ok || fieldValue == "" {
			continue
		}

		// Check for change data
		changeData := checkForChangeData(cache, fieldName, fieldValue)

		// Perform lookup
		lookupData := performLookup(cfg, token, cache, fieldName, fieldValue, rule)
		if lookupData == nil {
			continue
		}

		// Apply response mappings
		for srcField, dstField := range rule.ResponseMapping {
			if value, exists := lookupData[srcField]; exists {
				event.Details[dstField] = value
			}
		}

		// Add change fields if available
		if changeData != nil {
			addChangeFields(event, rule, changeData, lookupData, fieldName)
		}
	}
}

// The rest of the functions follow similar idiomatic patterns...
// [Additional functions would continue here with proper Go idioms]

// showHelpMessage displays usage information
func showHelpMessage() {
	fmt.Print(`Bitwarden Event Forwarder v` + Version + `

USAGE:
  bw-events [options]

FLAGS:
  --help                 Show this help message
  --version              Show version information  
  --validate             Validate configuration and exit
  --test                 Test connections and exit
  --config FILE          Load configuration from JSON file

REQUIRED:
  --client-id ID         Bitwarden API Client ID
  --client-secret SECRET Bitwarden API Client Secret

OPTIONS:
  --api-url URL          API base URL (default: https://api.bitwarden.com)
  --identity-url URL     Identity URL (default: https://identity.bitwarden.com)
  --syslog-server HOST   Syslog server (default: localhost)
  --syslog-port PORT     Syslog port (default: 514)
  --syslog-proto PROTO   Protocol: tcp/udp (default: tcp)
  --interval SECONDS     Fetch interval (default: 60)
  --conn-timeout SECONDS Connection timeout (default: 30)
  --log-level LEVEL      Log level: debug/info/warn/error (default: info)
  --log-file FILE        Log file path (default: stdout)

EXAMPLES:
  bw-events --client-id "id" --client-secret "secret" --syslog-server "10.1.1.100"
  bw-events --test --config /etc/bitwarden/config.json
  bw-events --validate --config /etc/bitwarden/config.json

`)
}

// showVersionInfo displays version information
func showVersionInfo() {
	fmt.Printf(`Bitwarden Event Forwarder
Version: %s
Build Date: %s
Features: CEF formatting, change detection, intelligent caching
`, Version, BuildDate)
}

// invalidateCacheForEvent performs smart cache invalidation based on event types
func invalidateCacheForEvent(cache *LookupCache, mapping FieldMapping, event *Event) {
	cacheTypes, exists := mapping.CacheInvalidationRules[event.Type]
	if !exists {
		return
	}

	log.Printf("Event type %d detected, performing cache refresh with change detection", event.Type)

	for _, cacheType := range cacheTypes {
		switch cacheType {
		case "policyId":
			performPolicyChangeDetection(cache, event)
		case "memberId":
			performMemberChangeDetection(cache, event)
		case "groupId":
			performGroupChangeDetection(cache, event)
		case "collectionId":
			performCollectionChangeDetection(cache, event)
		default:
			log.Printf("Unknown cache type for change detection: %s", cacheType)
		}
	}
}

// performPolicyChangeDetection captures old policy data before cache invalidation
func performPolicyChangeDetection(cache *LookupCache, event *Event) {
	if event.PolicyID == "" {
		return
	}

	// Capture current cached state
	oldData, hasOldData := cache.Get("policyDetails", event.PolicyID)

	// Invalidate cache entries
	cache.mu.Lock()
	if cache.cache["policyDetails"] != nil {
		delete(cache.cache["policyDetails"], event.PolicyID)
	}
	if cache.cache["policyIdToType"] != nil {
		delete(cache.cache["policyIdToType"], "mapping")
	}
	cache.mu.Unlock()

	log.Printf("Policy cache invalidated for ID: %s, had cached data: %v", event.PolicyID, hasOldData)

	// Store change data for enrichment
	if hasOldData {
		changeData := map[string]interface{}{
			"hasChanges": true,
			"oldData":    oldData,
		}
		cache.Set("policyChanges", event.PolicyID, changeData)
		log.Printf("Stored old policy data for change detection: %s", event.PolicyID)
	}
}

// performMemberChangeDetection captures old member data before cache invalidation
func performMemberChangeDetection(cache *LookupCache, event *Event) {
	if event.MemberID == "" {
		return
	}

	oldData, hasOldData := cache.Get("memberId", event.MemberID)

	cache.mu.Lock()
	if cache.cache["memberId"] != nil {
		delete(cache.cache["memberId"], event.MemberID)
	}
	cache.mu.Unlock()

	if hasOldData {
		changeData := map[string]interface{}{
			"hasChanges": true,
			"oldData":    oldData,
		}
		cache.Set("memberChanges", event.MemberID, changeData)
		log.Printf("Stored old member data for change detection: %s", event.MemberID)
	}
}

// performGroupChangeDetection captures old group data before cache invalidation
func performGroupChangeDetection(cache *LookupCache, event *Event) {
	if event.GroupID == "" {
		return
	}

	oldData, hasOldData := cache.Get("groupId", event.GroupID)

	cache.mu.Lock()
	if cache.cache["groupId"] != nil {
		delete(cache.cache["groupId"], event.GroupID)
	}
	cache.mu.Unlock()

	if hasOldData {
		changeData := map[string]interface{}{
			"hasChanges": true,
			"oldData":    oldData,
		}
		cache.Set("groupChanges", event.GroupID, changeData)
		log.Printf("Stored old group data for change detection: %s", event.GroupID)
	}
}

// performCollectionChangeDetection captures old collection data before cache invalidation
func performCollectionChangeDetection(cache *LookupCache, event *Event) {
	if event.CollectionID == "" {
		return
	}

	oldData, hasOldData := cache.Get("collectionId", event.CollectionID)

	cache.mu.Lock()
	if cache.cache["collectionId"] != nil {
		delete(cache.cache["collectionId"], event.CollectionID)
	}
	cache.mu.Unlock()

	if hasOldData {
		changeData := map[string]interface{}{
			"hasChanges": true,
			"oldData":    oldData,
		}
		cache.Set("collectionChanges", event.CollectionID, changeData)
		log.Printf("Stored old collection data for change detection: %s", event.CollectionID)
	}
}

// checkForChangeData retrieves and cleans up change detection data
func checkForChangeData(cache *LookupCache, fieldName, fieldValue string) map[string]interface{} {
	changesCacheKey := fieldName + "Changes"
	changeData, ok := cache.Get(changesCacheKey, fieldValue)
	if !ok {
		return nil
	}

	// Clean up the change data after using it
	cache.mu.Lock()
	if cache.cache[changesCacheKey] != nil {
		delete(cache.cache[changesCacheKey], fieldValue)
	}
	cache.mu.Unlock()

	return changeData
}

// performLookup executes API lookups with caching
func performLookup(cfg Configuration, token *OAuth2Token, cache *LookupCache, cacheKey, id string, rule LookupRule) map[string]interface{} {
	// Check cache first
	if data, ok := cache.Get(cacheKey, id); ok {
		return data
	}

	// Special handling for policies
	if cacheKey == "policyId" {
		return performPolicyLookup(cfg, token, cache, id)
	}

	// Standard API lookup
	endpoint := strings.Replace(rule.Endpoint, "{id}", id, 1)
	url := cfg.APIBaseURL + endpoint

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Printf("Failed to create lookup request for %s: %v", cacheKey, err)
		return nil
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("User-Agent", UserAgent)

	client := &http.Client{Timeout: time.Duration(cfg.ConnTimeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Lookup request failed for %s: %v", cacheKey, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Lookup failed for %s (%s): %d %s", cacheKey, id, resp.StatusCode, body)
		return nil
	}

	var lookupResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&lookupResp); err != nil {
		log.Printf("Failed to decode lookup response for %s: %v", cacheKey, err)
		return nil
	}

	// Cache the result
	cache.Set(cacheKey, id, lookupResp)
	return lookupResp
}

// performPolicyLookup handles the special case of policy lookups
func performPolicyLookup(cfg Configuration, token *OAuth2Token, cache *LookupCache, policyID string) map[string]interface{} {
	// Check if we have the specific policy cached
	if policy, ok := cache.Get("policyDetails", policyID); ok {
		return policy
	}

	// Get ID->Type mapping
	idToTypeMap := getPolicyIDToTypeMapping(cfg, token, cache)
	if idToTypeMap == nil {
		return nil
	}

	// Get policy type for this ID
	policyType, exists := idToTypeMap[policyID]
	if !exists {
		log.Printf("Policy ID %s not found in policy list", policyID)
		return nil
	}

	// Fetch detailed policy information
	url := fmt.Sprintf("%s/public/policies/%d", cfg.APIBaseURL, policyType)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Printf("Failed to create policy detail request: %v", err)
		return nil
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("User-Agent", UserAgent)

	client := &http.Client{Timeout: time.Duration(cfg.ConnTimeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Policy detail request failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Policy detail request failed: %d %s", resp.StatusCode, body)
		return nil
	}

	var policyDetail map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&policyDetail); err != nil {
		log.Printf("Failed to decode policy detail response: %v", err)
		return nil
	}

	// Add human-readable policy type name
	if policyTypeFloat, ok := policyDetail["type"].(float64); ok {
		policyDetail["policyTypeName"] = getPolicyTypeName(int(policyTypeFloat))
	}

	// Cache the detailed policy information
	cache.Set("policyDetails", policyID, policyDetail)
	return policyDetail
}

// getPolicyIDToTypeMapping builds and caches the policy ID to Type mapping
func getPolicyIDToTypeMapping(cfg Configuration, token *OAuth2Token, cache *LookupCache) map[string]int {
	// Check if we have the mapping cached
	if cachedMapping, ok := cache.Get("policyIdToType", "mapping"); ok {
		if mapping, ok := cachedMapping.(map[string]int); ok {
			return mapping
		}
	}

	// Fetch all policies to build the mapping
	idToTypeMap := make(map[string]int)

	url := cfg.APIBaseURL + "/public/policies"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Printf("Failed to create policies list request: %v", err)
		return nil
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("User-Agent", UserAgent)

	client := &http.Client{Timeout: time.Duration(cfg.ConnTimeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Policies list request failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Policies list request failed: %d %s", resp.StatusCode, body)
		return nil
	}

	var policiesResp struct {
		Object string                   `json:"object"`
		Data   []map[string]interface{} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&policiesResp); err != nil {
		log.Printf("Failed to decode policies list response: %v", err)
		return nil
	}

	// Build ID->Type mapping
	for _, policy := range policiesResp.Data {
		if id, idOK := policy["id"].(string); idOK {
			if policyType, typeOK := policy["type"].(float64); typeOK {
				idToTypeMap[id] = int(policyType)
			}
		}
	}

	// Cache the mapping
	cache.Set("policyIdToType", "mapping", idToTypeMap)
	return idToTypeMap
}

// getPolicyTypeName returns human-readable policy type names
func getPolicyTypeName(policyType int) string {
	policyTypeNames := map[int]string{
		0:  "TwoFactorAuthentication",
		1:  "MasterPassword",
		2:  "PasswordGenerator",
		3:  "SingleOrg",
		4:  "RequireSso",
		5:  "PersonalOwnership",
		6:  "DisableSend",
		7:  "SendOptions",
		8:  "ResetPassword",
		9:  "MaximumVaultTimeout",
		10: "DisablePersonalVaultExport",
		11: "ActivateAutofill",
	}

	if name, exists := policyTypeNames[policyType]; exists {
		return name
	}
	return fmt.Sprintf("UnknownPolicyType_%d", policyType)
}

// addChangeFields adds old/new value comparison fields to events
func addChangeFields(event *Event, rule LookupRule, changeData, newData map[string]interface{}, fieldType string) {
	oldDataInterface, ok := changeData["oldData"]
	if !ok {
		return
	}

	oldData, ok := oldDataInterface.(map[string]interface{})
	if !ok {
		return
	}

	var changedFields, oldValues, newValues, fieldNames []string

	// Compare each mapped field and collect changes
	for srcField, dstField := range rule.ResponseMapping {
		oldValue := getStringValue(oldData[srcField])
		newValue := getStringValue(newData[srcField])

		// Only process if values are different
		if oldValue != newValue {
			changedFields = append(changedFields, dstField)

			// Format as "fieldName: value" for better readability
			oldValueFormatted := fmt.Sprintf("%s: %s", srcField, oldValue)
			newValueFormatted := fmt.Sprintf("%s: %s", srcField, newValue)

			oldValues = append(oldValues, escapeCommaValue(oldValueFormatted))
			newValues = append(newValues, escapeCommaValue(newValueFormatted))
			fieldNames = append(fieldNames, srcField)

			// Add individual field changes
			event.Details[dstField+"_oldValue"] = oldValue
			event.Details[dstField+"_newValue"] = newValue
			event.Details[dstField+"_changed"] = "true"

			log.Printf("Change detected in %s.%s: '%s' -> '%s'", fieldType, srcField, oldValue, newValue)
		}
	}

	// Add consolidated change summary if there are changes
	if len(changedFields) > 0 {
		event.Details["hasDataChanges"] = "true"
		event.Details["changeType"] = fieldType
		event.Details["changedFields"] = strings.Join(changedFields, ",")
		event.Details["oldValues"] = strings.Join(oldValues, ", ")
		event.Details["newValues"] = strings.Join(newValues, ", ")
		event.Details["changeCount"] = fmt.Sprintf("%d", len(changedFields))

		log.Printf("Summary: %d fields changed in %s: %v", len(changedFields), fieldType, fieldNames)
	}
}

// getStringValue safely converts interface{} to string
func getStringValue(value interface{}) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%v", value)
}

// escapeCommaValue escapes values for comma-delimited lists
func escapeCommaValue(value string) string {
	if strings.ContainsAny(value, ",;|\"") {
		escaped := strings.ReplaceAll(value, "\"", "\\\"")
		return "\"" + escaped + "\""
	}
	return value
}

// formatEventAsCEF formats an event as CEF message
func formatEventAsCEF(event Event, mapping FieldMapping, eventTypeNames map[string]string) string {
	// Get friendly event name
	eventName := "Unknown Event"
	if friendlyName, ok := eventTypeNames[fmt.Sprintf("%d", event.Type)]; ok {
		eventName = friendlyName
	}

	// CEF Header
	header := fmt.Sprintf("CEF:0|%s|%s|%s|%d|%s|Medium|",
		mapping.CEFVendor, mapping.CEFProduct, mapping.CEFVersion,
		event.Type, eventName)

	// CEF Extensions
	extensions := make(map[string]string)

	// Map event details to CEF fields
	for srcField, dstField := range mapping.FieldMappings {
		if value, ok := event.Details[srcField]; ok && value != nil {
			extensions[dstField] = fmt.Sprintf("%v", value)
		}
	}

	// Build ordered extension string
	var parts []string

	// Add ordered fields first
	for _, field := range mapping.OrderedFields {
		if value, ok := extensions[field]; ok {
			parts = append(parts, fmt.Sprintf("%s=%s", field, escapeValue(value)))
			delete(extensions, field)
		}
	}

	// Add remaining fields in sorted order
	var remainingKeys []string
	for key := range extensions {
		remainingKeys = append(remainingKeys, key)
	}
	sort.Strings(remainingKeys)

	for _, key := range remainingKeys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, escapeValue(extensions[key])))
	}

	return header + strings.Join(parts, " ")
}

// escapeValue escapes CEF values
func escapeValue(value string) string {
	replacements := []struct{ old, new string }{
		{"\\", "\\\\"},
		{"=", "\\="},
		{"|", "\\|"},
		{"\n", "\\n"},
		{"\r", "\\r"},
	}

	result := value
	for _, r := range replacements {
		result = strings.ReplaceAll(result, r.old, r.new)
	}
	return result
}

// sendToSyslogWithRetry sends a message to syslog with retry logic
func sendToSyslogWithRetry(cfg Configuration, message string, maxRetries int) error {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := sendToSyslog(cfg, message); err == nil {
			return nil
		} else {
			lastErr = err
		}

		if attempt < maxRetries {
			backoff := time.Duration(attempt) * time.Second
			time.Sleep(backoff)
		}
	}

	return fmt.Errorf("syslog send failed after %d attempts: %w", maxRetries, lastErr)
}

// sendToSyslog sends a message to the configured syslog server
func sendToSyslog(cfg Configuration, message string) error {
	address := fmt.Sprintf("%s:%s", cfg.SyslogServer, cfg.SyslogPort)
	conn, err := net.DialTimeout(cfg.SyslogProtocol, address, time.Duration(cfg.ConnTimeout)*time.Second)
	if err != nil {
		return fmt.Errorf("syslog connection failed: %w", err)
	}
	defer conn.Close()

	if len(message) > cfg.MaxMsgSize {
		message = message[:cfg.MaxMsgSize]
	}

	_, err = fmt.Fprintln(conn, message)
	return err
}

// loadConfigFromFile loads additional configuration from JSON file
func loadConfigFromFile(cfg *Configuration, filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	var fileConfig map[string]interface{}
	if err := json.Unmarshal(data, &fileConfig); err != nil {
		return fmt.Errorf("parse config file: %w", err)
	}

	// Override configuration with file values
	configMap := map[string]*string{
		"api_base_url":     &cfg.APIBaseURL,
		"identity_url":     &cfg.IdentityURL,
		"client_id":        &cfg.ClientID,
		"client_secret":    &cfg.ClientSecret,
		"syslog_protocol":  &cfg.SyslogProtocol,
		"syslog_server":    &cfg.SyslogServer,
		"syslog_port":      &cfg.SyslogPort,
		"log_level":        &cfg.LogLevel,
		"log_file":         &cfg.LogFile,
		"marker_file":      &cfg.MarkerFile,
		"field_map_file":   &cfg.FieldMapFile,
		"event_map_file":   &cfg.EventMapFile,
	}

	for key, ptr := range configMap {
		if val, ok := fileConfig[key].(string); ok {
			*ptr = val
		}
	}

	// Handle numeric fields
	if val, ok := fileConfig["fetch_interval"].(float64); ok {
		cfg.FetchInterval = int(val)
	}
	if val, ok := fileConfig["max_msg_size"].(float64); ok {
		cfg.MaxMsgSize = int(val)
	}
	if val, ok := fileConfig["max_pagination"].(float64); ok {
		cfg.MaxPagination = int(val)
	}
	if val, ok := fileConfig["conn_timeout"].(float64); ok {
		cfg.ConnTimeout = int(val)
	}

	return nil
}

// validateConfiguration validates the configuration
func validateConfiguration(cfg Configuration) error {
	var errors []string

	// Required fields
	if cfg.ClientID == "" {
		errors = append(errors, "Client ID is required (--client-id or BW_CLIENT_ID)")
	}
	if cfg.ClientSecret == "" {
		errors = append(errors, "Client Secret is required (--client-secret or BW_CLIENT_SECRET)")
	}

	// URL validation
	if !isValidURL(cfg.APIBaseURL) {
		errors = append(errors, fmt.Sprintf("Invalid API URL: %s", cfg.APIBaseURL))
	}
	if !isValidURL(cfg.IdentityURL) {
		errors = append(errors, fmt.Sprintf("Invalid Identity URL: %s", cfg.IdentityURL))
	}

	// Syslog validation
	if cfg.SyslogProtocol != "tcp" && cfg.SyslogProtocol != "udp" {
		errors = append(errors, "Syslog protocol must be 'tcp' or 'udp'")
	}
	if cfg.SyslogServer == "" {
		errors = append(errors, "Syslog server is required")
	}
	if !isValidPort(cfg.SyslogPort) {
		errors = append(errors, fmt.Sprintf("Invalid syslog port: %s", cfg.SyslogPort))
	}

	// Numeric validation
	validations := []struct {
		value int
		min   int
		name  string
	}{
		{cfg.FetchInterval, 1, "Fetch interval"},
		{cfg.ConnTimeout, 1, "Connection timeout"},
		{cfg.MaxMsgSize, 512, "Maximum message size"},
		{cfg.MaxPagination, 1, "Maximum pagination"},
	}

	for _, v := range validations {
		if v.value < v.min {
			errors = append(errors, fmt.Sprintf("%s must be at least %d", v.name, v.min))
		}
	}

	// Log level validation
	validLogLevels := []string{"debug", "info", "warn", "error"}
	if !contains(validLogLevels, cfg.LogLevel) {
		errors = append(errors, fmt.Sprintf("Invalid log level: %s (must be one of: %v)", cfg.LogLevel, validLogLevels))
	}

	// File accessibility checks
	fileChecks := []struct {
		path      string
		name      string
		mustExist bool
	}{
		{cfg.FieldMapFile, "field mapping", true},
		{cfg.EventMapFile, "event type mapping", true},
		{cfg.MarkerFile, "marker", false},
	}

	for _, check := range fileChecks {
		if err := checkFileAccessibility(check.path, check.name, check.mustExist); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if cfg.LogFile != "" {
		if err := checkFileAccessibility(cfg.LogFile, "log", false); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// Helper validation functions
func isValidURL(u string) bool {
	return u != "" && (strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://"))
}

func isValidPort(port string) bool {
	if port == "" {
		return false
	}
	var p int
	n, err := fmt.Sscanf(port, "%d", &p)
	return err == nil && n == 1 && p > 0 && p <= 65535
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func checkFileAccessibility(filename, fileType string, mustExist bool) error {
	if filename == "" {
		return fmt.Errorf("%s file path is empty", fileType)
	}

	// Check if directory exists and is writable
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create directory for %s file: %w", fileType, err)
	}

	// Check if file exists when required
	if mustExist {
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			return fmt.Errorf("%s file does not exist: %s", fileType, filename)
		}
	}

	return nil
}

// testConnections tests all required connections
func testConnections(cfg Configuration) error {
	fmt.Println("🔍 Testing configuration and connections...")

	// Test Bitwarden API authentication
	fmt.Print("  Testing Bitwarden API authentication... ")
	token, err := fetchOAuth2Token(cfg)
	if err != nil {
		fmt.Println("❌ FAILED")
		return fmt.Errorf("Bitwarden API authentication failed: %w", err)
	}
	fmt.Printf("✅ SUCCESS (expires: %s)\n", token.Expiry.Format("2006-01-02 15:04:05"))

	// Test Bitwarden API connectivity
	fmt.Print("  Testing Bitwarden API connectivity... ")
	if err := testBitwardenAPI(cfg, &token); err != nil {
		fmt.Println("❌ FAILED")
		return fmt.Errorf("Bitwarden API connectivity failed: %w", err)
	}
	fmt.Println("✅ SUCCESS")

	// Test Syslog connectivity
	fmt.Print("  Testing Syslog connectivity... ")
	if err := testSyslogConnection(cfg); err != nil {
		fmt.Println("❌ FAILED")
		return fmt.Errorf("Syslog connectivity failed: %w", err)
	}
	fmt.Println("✅ SUCCESS")

	// Test configuration files
	fmt.Print("  Testing configuration files... ")
	if err := testConfigurationFiles(cfg); err != nil {
		fmt.Println("❌ FAILED")
		return fmt.Errorf("Configuration files test failed: %w", err)
	}
	fmt.Println("✅ SUCCESS")

	return nil
}

// testBitwardenAPI tests API connectivity
func testBitwardenAPI(cfg Configuration, token *OAuth2Token) error {
	url := cfg.APIBaseURL + "/public/events?start=2025-01-01T00:00:00.000Z&end=2025-01-01T00:01:00.000Z"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("User-Agent", UserAgent)

	client := &http.Client{Timeout: time.Duration(cfg.ConnTimeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, body)
	}

	return nil
}

// testSyslogConnection tests syslog connectivity
func testSyslogConnection(cfg Configuration) error {
	address := fmt.Sprintf("%s:%s", cfg.SyslogServer, cfg.SyslogPort)
	conn, err := net.DialTimeout(cfg.SyslogProtocol, address, time.Duration(cfg.ConnTimeout)*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Send test message
	testMessage := fmt.Sprintf("CEF:0|BitwardenEventForwarder|Test|1.0|0|Connection Test|Low|rt=%s",
		time.Now().Format("2006-01-02T15:04:05.000Z"))
	_, err = fmt.Fprintln(conn, testMessage)
	return err
}

// testConfigurationFiles tests configuration file validity
func testConfigurationFiles(cfg Configuration) error {
	// Test field mapping file
	fieldMapping := loadFieldMapping(cfg.FieldMapFile)
	if len(fieldMapping.FieldMappings) == 0 {
		return fmt.Errorf("field mapping file appears to be empty or invalid")
	}

	// Test event mapping file
	eventMapping := loadEventTypeNames(cfg.EventMapFile)
	if len(eventMapping) == 0 {
		return fmt.Errorf("event mapping file appears to be empty or invalid")
	}

	return nil
}
