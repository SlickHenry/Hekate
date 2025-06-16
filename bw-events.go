package main

import (
	"container/ring"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Configuration struct {
	APIBaseURL         string
	IdentityURL        string
	ClientID           string
	ClientSecret       string
	SyslogProtocol     string
	SyslogServer       string
	SyslogPort         string
	LogLevel           string
	LogFile            string
	FetchInterval      int
	ConnTimeout        int
	MaxMsgSize         int
	MarkerFile         string
	FieldMapFile       string
	EventMapFile       string
	Verbose            bool
	MaxRetries         int
	RetryDelay         int
	HealthCheckPort    int
	TestMode           bool
	ValidateMode       bool
	ShowVersion        bool
	EventCacheSize       int
	EventCacheWindow     int
	EnableEventCache     bool
	InitialLookbackHours int
	PollOverlapMinutes   int
	MaxEventsPerPoll     int
}

type FieldMapping struct {
	OrderedFields          []string                    `json:"ordered_fields"`
	FieldMappings          map[string]string           `json:"field_mappings"`
	Lookups                map[string]LookupConfig     `json:"lookups"`
	CacheInvalidationRules map[string][]string         `json:"cache_invalidation_rules"`
	EventFiltering         EventFilter                 `json:"event_filtering"`
	Statistics             StatisticsConfig            `json:"statistics"`
	CEFVendor              string                      `json:"cef_vendor"`
	CEFProduct             string                      `json:"cef_product"`
	CEFVersion             string                      `json:"cef_version"`
}

type EventFilter struct {
	Mode               string                  `json:"mode"`
	ExcludedEvents     []string                `json:"excluded_events"`
	IncludedEvents     []string                `json:"included_events"`
	RateLimiting       map[string]RateLimit    `json:"rate_limiting"`
	PriorityEvents     []string                `json:"priority_events"`
	UserFiltering      UserFilter              `json:"user_filtering"`
}

type RateLimit struct {
	MaxPerHour int  `json:"max_per_hour"`
	Enabled    bool `json:"enabled"`
}

type UserFilter struct {
	ExcludeServiceAccounts bool     `json:"exclude_service_accounts"`
	ExcludeUsers          []string `json:"exclude_users"`
	IncludeOnlyUsers      []string `json:"include_only_users"`
}

type StatisticsConfig struct {
	EnableDetailedLogging   bool `json:"enable_detailed_logging"`
	LogIntervalEvents       int  `json:"log_interval_events"`
	TrackCacheMetrics       bool `json:"track_cache_metrics"`
	TrackPerformanceMetrics bool `json:"track_performance_metrics"`
}

type LookupConfig struct {
	Endpoint        string            `json:"endpoint"`
	ResponseMapping map[string]string `json:"response_mapping"`
}

type ServiceStats struct {
	sync.RWMutex
	StartTime              time.Time
	LastSuccessfulRun      time.Time
	TotalEventsForwarded   int64
	TotalEventsFiltered    int64
	TotalEventsDropped     int64
	TotalAPIRequests       int64
	FailedAPIRequests      int64
	TotalRetryAttempts     int64
	SuccessfulRecoveries   int64
	SyslogReconnects       int64
	CacheHits              int64
	CacheMisses            int64
	LookupFailures         int64
	ChangeDetectionEvents  int64
	MarkerFileUpdates      int64
	LastError              string
	LastErrorTime          time.Time
	LastMarker             string
	CurrentPollDuration    time.Duration
	AverageEventsPerSecond float64
}

type RateLimitTracker struct {
	sync.RWMutex
	EventCounts map[string][]time.Time
}

type OAuthToken struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresIn   int       `json:"expires_in"`
	ExpiresAt   time.Time `json:"-"`
}

// FIXED BitwardenEvent struct to match API response
type BitwardenEvent struct {
	Object       string    `json:"object"`
	Type         int       `json:"type"`
	ItemID       *string   `json:"itemId"`
	CollectionID *string   `json:"collectionId"`
	GroupID      *string   `json:"groupId"`
	PolicyID     *string   `json:"policyId"`
	MemberID     *string   `json:"memberId"`
	ActingUserID *string   `json:"actingUserId"`
	InstallationID *string `json:"installationId"`
	Date         time.Time `json:"date"`
	Device       int       `json:"device"`
	IPAddress    *string   `json:"ipAddress"`
}

type BitwardenEventsResponse struct {
	Object            string           `json:"object"`
	Data              []BitwardenEvent `json:"data"`
	ContinuationToken *string          `json:"continuationToken"`
}

type SyslogWriter struct {
	protocol       string
	address        string
	conn           net.Conn
	reconnectCount int
	lastReconnect  time.Time
	maxReconnects  int
	reconnectDelay time.Duration
}

type LookupCache struct {
	sync.RWMutex
	data map[string]map[string]interface{}
}

type CacheStats struct {
	Hits   int
	Misses int
}

type LookupStats struct {
	Failures int
	Success  int
}

type ChangeStats struct {
	ChangeEvents int
}

type EventCache struct {
	sync.RWMutex
	processedEvents map[string]time.Time
	eventRing       *ring.Ring
	maxCacheSize    int
	cacheWindow     time.Duration
}

type EventCacheStats struct {
	DuplicatesDetected int64
	CacheHits          int64
	CacheMisses        int64
	CacheSize          int
}

type TimeBasedMarker struct {
	LastEventTime time.Time `json:"last_event_time"`
	LastEventID   string    `json:"last_event_id"`
	PollCount     int64     `json:"poll_count"`
}

var (
	serviceStats     = &ServiceStats{StartTime: time.Now()}
	rateLimitTracker = &RateLimitTracker{EventCounts: make(map[string][]time.Time)}
	lookupCache      = &LookupCache{data: make(map[string]map[string]interface{})}
	ctx              context.Context
	cancel           context.CancelFunc
	currentToken     *OAuthToken
	eventTypeMap     map[string]string
	eventCache       *EventCache
	eventCacheStats  = &EventCacheStats{}
	timeBasedMarker  = &TimeBasedMarker{}
)

func main() {
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	config := loadConfig()

	if config.ShowVersion {
		fmt.Println("Bitwarden Event Forwarder v2.0.0 - Enhanced with Filtering & Statistics")
		return
	}

	if config.ValidateMode {
		if err := validateConfig(config); err != nil {
			log.Fatalf("❌ Configuration validation failed: %v", err)
		}
		log.Println("✅ Configuration is valid")
		return
	}

	if config.TestMode {
		if err := runConnectionTests(config); err != nil {
			log.Fatalf("❌ Connection tests failed: %v", err)
		}
		log.Println("✅ All connection tests passed")
		return
	}

	if err := setupLogging(config); err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}

	logServiceStartup(config)

	if err := validateConfig(config); err != nil {
		log.Fatalf("❌ Configuration validation failed: %v", err)
	}

	fieldMapping := loadFieldMapping(config.FieldMapFile)
	// Initialize event cache
	if config.EnableEventCache {
		cacheWindow := time.Duration(config.EventCacheWindow) * time.Second
		eventCache = NewEventCache(config.EventCacheSize, cacheWindow)
		log.Printf("🧠 Event deduplication cache initialized (size: %d, window: %v)", 
			config.EventCacheSize, cacheWindow)
		
		// Start cleanup goroutine
		go eventCache.cleanupExpired()
	} else {
		log.Println("⚠️  Event deduplication cache disabled")
	}
	eventTypeMap = loadEventTypeMap(config.EventMapFile)

	syslogWriter, err := NewSyslogWriter(config.SyslogProtocol,
		fmt.Sprintf("%s:%s", config.SyslogServer, config.SyslogPort), config)
	if err != nil {
		log.Fatalf("❌ Failed to initialize syslog connection: %v", err)
	}
	defer syslogWriter.Close()

	log.Println("✅ Syslog connectivity verified")

	if err := authenticateWithBitwarden(config); err != nil {
		log.Fatalf("❌ Failed to authenticate with Bitwarden: %v", err)
	}

	log.Printf("✅ Successfully authenticated (expires: %s)", currentToken.ExpiresAt.Format("2006-01-02 15:04:05"))

	log.Println("💾 Cache initialized")
	log.Printf("🗺️  Field mappings loaded (%d lookups)", len(fieldMapping.Lookups))
	log.Printf("📝 Event types loaded (%d types)", len(eventTypeMap))

	timeBasedMarker := loadTimeBasedMarker(config.MarkerFile)
	if timeBasedMarker.LastEventID != "" {
		log.Printf("📍 Resuming from marker: %s (Poll #%d)", 
			timeBasedMarker.LastEventTime.Format("2006-01-02 15:04:05"), timeBasedMarker.PollCount)
	} else {
		log.Printf("🆕 Starting fresh - will collect from %s", 
			timeBasedMarker.LastEventTime.Format("2006-01-02 15:04:05"))
	}

	if config.HealthCheckPort > 0 {
		go startHealthCheckServer(config.HealthCheckPort)
		log.Printf("🏥 Health check server started on port %d", config.HealthCheckPort)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	log.Println("🎯 Starting event polling...")

	ticker := time.NewTicker(time.Duration(config.FetchInterval) * time.Second)
	defer ticker.Stop()

	processEventsWithRecovery(config, fieldMapping, syslogWriter, timeBasedMarker)
	
	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, shutting down...")
			return

		case <-ticker.C:
			timeBasedMarker = processEventsWithRecovery(config, fieldMapping, syslogWriter, timeBasedMarker)

		case sig := <-sigChan:
			log.Printf("📨 Received signal %v, initiating graceful shutdown...", sig)

			if sig == syscall.SIGHUP {
				log.Println("🔄 SIGHUP received - reloading configuration")
				fieldMapping = loadFieldMapping(config.FieldMapFile)
				eventTypeMap = loadEventTypeMap(config.EventMapFile)
				log.Println("✅ Configuration reloaded")
				continue
			}

			log.Println("💾 Saving final state and shutting down...")
			cancel()
			return
		}
	}
}

func loadConfig() Configuration {
	apiURL := flag.String("api-url", getEnvOrDefault("BW_API_URL", "https://api.bitwarden.com"), "Bitwarden API base URL")
	identityURL := flag.String("identity-url", getEnvOrDefault("BW_IDENTITY_URL", "https://identity.bitwarden.com"), "Bitwarden Identity URL")
	clientID := flag.String("client-id", getEnvOrDefault("BW_CLIENT_ID", ""), "Bitwarden API Client ID")
	clientSecret := flag.String("client-secret", getEnvOrDefault("BW_CLIENT_SECRET", ""), "Bitwarden API Client Secret")
	syslogProto := flag.String("syslog-proto", getEnvOrDefault("SYSLOG_PROTOCOL", "tcp"), "Syslog protocol (tcp/udp)")
	syslogServer := flag.String("syslog-server", getEnvOrDefault("SYSLOG_SERVER", "localhost"), "Syslog server address")
	syslogPort := flag.String("syslog-port", getEnvOrDefault("SYSLOG_PORT", "514"), "Syslog server port")
	logLevel := flag.String("log-level", getEnvOrDefault("LOG_LEVEL", "info"), "Log level")
	logFile := flag.String("log-file", getEnvOrDefault("LOG_FILE", ""), "Log file path")
	fetchInterval := flag.Int("interval", getEnvOrIntDefault("FETCH_INTERVAL", 60), "Event fetch interval in seconds")
	connTimeout := flag.Int("conn-timeout", getEnvOrIntDefault("CONNECTION_TIMEOUT", 30), "Connection timeout in seconds")
	maxMsgSize := flag.Int("max-msg-size", getEnvOrIntDefault("MAX_MSG_SIZE", 8192), "Maximum syslog message size")
	markerFile := flag.String("marker-file", getEnvOrDefault("MARKER_FILE", "bitwarden_marker.txt"), "Event marker file")
	fieldMapFile := flag.String("field-map", getEnvOrDefault("FIELD_MAP_FILE", "bitwarden_field_map.json"), "Field mapping file")
	eventMapFile := flag.String("event-map", getEnvOrDefault("EVENT_MAP_FILE", "bitwarden_event_map.json"), "Event type mapping file")
	verbose := flag.Bool("verbose", getEnvOrBoolDefault("VERBOSE", false), "Enable verbose output")
	maxRetries := flag.Int("max-retries", getEnvOrIntDefault("MAX_RETRIES", 3), "Maximum retry attempts")
	retryDelay := flag.Int("retry-delay", getEnvOrIntDefault("RETRY_DELAY", 5), "Retry delay in seconds")
	healthCheckPort := flag.Int("health-port", getEnvOrIntDefault("HEALTH_CHECK_PORT", 8080), "Health check port (0 to disable)")
	testMode := flag.Bool("test", false, "Test connections and dependencies")
	validateMode := flag.Bool("validate", false, "Validate configuration and exit")
	showVersion := flag.Bool("version", false, "Show version information")
	eventCacheSize := flag.Int("event-cache-size", getEnvOrIntDefault("EVENT_CACHE_SIZE", 10000), "Maximum number of event IDs to cache")
	eventCacheWindow := flag.Int("event-cache-window", getEnvOrIntDefault("EVENT_CACHE_WINDOW", 3600), "Event cache window in seconds")
	enableEventCache := flag.Bool("enable-event-cache", getEnvOrBoolDefault("ENABLE_EVENT_CACHE", true), "Enable event deduplication cache")
	initialLookback := flag.Int("initial-lookback-hours", getEnvOrIntDefault("INITIAL_LOOKBACK_HOURS", 24), "Hours to look back for initial poll")
	pollOverlap := flag.Int("poll-overlap-minutes", getEnvOrIntDefault("POLL_OVERLAP_MINUTES", 5), "Minutes to overlap between polls")
	maxEvents := flag.Int("max-events-per-poll", getEnvOrIntDefault("MAX_EVENTS_PER_POLL", 1000), "Maximum events to fetch per poll")

	flag.Parse()

	return Configuration{
		APIBaseURL:      *apiURL,
		IdentityURL:     *identityURL,
		ClientID:        *clientID,
		ClientSecret:    *clientSecret,
		SyslogProtocol:  *syslogProto,
		SyslogServer:    *syslogServer,
		SyslogPort:      *syslogPort,
		LogLevel:        *logLevel,
		LogFile:         *logFile,
		FetchInterval:   *fetchInterval,
		ConnTimeout:     *connTimeout,
		MaxMsgSize:      *maxMsgSize,
		MarkerFile:      *markerFile,
		FieldMapFile:    *fieldMapFile,
		EventMapFile:    *eventMapFile,
		Verbose:         *verbose,
		MaxRetries:      *maxRetries,
		RetryDelay:      *retryDelay,
		HealthCheckPort: *healthCheckPort,
		TestMode:        *testMode,
		ValidateMode:    *validateMode,
		ShowVersion:     *showVersion,
		EventCacheSize:       *eventCacheSize,
		EventCacheWindow:     *eventCacheWindow,
		EnableEventCache:     *enableEventCache,
		InitialLookbackHours: *initialLookback,
		PollOverlapMinutes:   *pollOverlap,
		MaxEventsPerPoll:     *maxEvents,
	}
}

func validateConfig(config Configuration) error {
	missing := []string{}
	if config.ClientID == "" {
		missing = append(missing, "BW_CLIENT_ID")
	}
	if config.ClientSecret == "" {
		missing = append(missing, "BW_CLIENT_SECRET")
	}
	if config.SyslogServer == "" {
		missing = append(missing, "SYSLOG_SERVER")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %v", missing)
	}
	if config.FetchInterval < 10 {
		return fmt.Errorf("fetch interval must be at least 10 seconds")
	}
	return nil
}

func setupLogging(config Configuration) error {
	var writers []io.Writer
	writers = append(writers, os.Stdout)

	if config.LogFile != "" {
		dir := filepath.Dir(config.LogFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}

		file, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		writers = append(writers, file)
	}

	if len(writers) > 1 {
		log.SetOutput(io.MultiWriter(writers...))
	} else {
		log.SetOutput(writers[0])
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	return nil
}

func logServiceStartup(config Configuration) {
	log.Printf("🚀 Starting Bitwarden Event Forwarder v2.0.0")
	log.Printf("📋 PID: %d", os.Getpid())
	log.Printf("🔐 API: %s", config.APIBaseURL)
	log.Printf("📡 Syslog: %s:%s (%s)", config.SyslogServer, config.SyslogPort, config.SyslogProtocol)
	log.Printf("⏱️  Interval: %ds", config.FetchInterval)
	log.Printf("📁 Marker: %s", config.MarkerFile)
	log.Printf("🗺️  Field Map: %s", config.FieldMapFile)
	log.Printf("📝 Event Map: %s", config.EventMapFile)
}

func runConnectionTests(config Configuration) error {
	log.Println("🔍 Testing configuration and connections...")

	log.Print("  Testing Bitwarden API authentication... ")
	if err := authenticateWithBitwarden(config); err != nil {
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	log.Println("✅ SUCCESS")

	log.Print("  Testing Bitwarden API connectivity... ")
	if err := testBitwardenAPI(config); err != nil {
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	log.Println("✅ SUCCESS")

	log.Print("  Testing Syslog connectivity... ")
	writer, err := NewSyslogWriter(config.SyslogProtocol, 
		fmt.Sprintf("%s:%s", config.SyslogServer, config.SyslogPort), config)
	if err != nil {
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	writer.Close()
	log.Println("✅ SUCCESS")

	log.Print("  Testing configuration files... ")
	if err := testConfigFiles(config); err != nil {
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	log.Println("✅ SUCCESS")

	log.Print("  Testing file permissions... ")
	if err := testFilePermissions(config); err != nil {
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	log.Println("✅ SUCCESS")

	return nil
}

func NewSyslogWriter(protocol, address string, config Configuration) (*SyslogWriter, error) {
	conn, err := net.DialTimeout(protocol, address, time.Duration(config.ConnTimeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to syslog server: %w", err)
	}

	return &SyslogWriter{
		protocol:       protocol,
		address:        address,
		conn:           conn,
		maxReconnects:  10,
		reconnectDelay: 5 * time.Second,
	}, nil
}

func (w *SyslogWriter) Write(message string) error {
	if w.conn == nil {
		return fmt.Errorf("no connection available")
	}
	_, err := fmt.Fprintln(w.conn, message)
	return err
}

func (w *SyslogWriter) Close() error {
	if w.conn != nil {
		return w.conn.Close()
	}
	return nil
}

func (w *SyslogWriter) Reconnect() error {
	if time.Since(w.lastReconnect) < w.reconnectDelay {
		return fmt.Errorf("reconnection rate limited")
	}

	if w.reconnectCount >= w.maxReconnects {
		return fmt.Errorf("max reconnection attempts exceeded")
	}

	if w.conn != nil {
		w.conn.Close()
	}

	conn, err := net.DialTimeout(w.protocol, w.address, 30*time.Second)
	if err != nil {
		w.reconnectCount++
		w.lastReconnect = time.Now()
		serviceStats.Lock()
		serviceStats.SyslogReconnects++
		serviceStats.Unlock()
		return fmt.Errorf("failed to reconnect to syslog server: %w", err)
	}

	w.conn = conn
	w.reconnectCount = 0
	w.lastReconnect = time.Now()
	log.Printf("✅ Successfully reconnected to syslog server")
	return nil
}

func authenticateWithBitwarden(config Configuration) error {
	tokenURL := config.IdentityURL + "/connect/token"

	deviceInfo := url.Values{}
	deviceInfo.Set("grant_type", "client_credentials")
	deviceInfo.Set("scope", "api.organization")
	deviceInfo.Set("client_id", config.ClientID)
	deviceInfo.Set("client_secret", config.ClientSecret)
	deviceInfo.Set("deviceType", "21")
	deviceInfo.Set("deviceName", "Bitwarden Event Forwarder")
	deviceInfo.Set("deviceIdentifier", generateDeviceIdentifier())

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(deviceInfo.Encode()))
	if err != nil {
		return fmt.Errorf("error creating auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Bitwarden-Event-Forwarder/2.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(body))
	}

	var token OAuthToken
	if err := json.Unmarshal(body, &token); err != nil {
		return fmt.Errorf("error parsing token response: %w", err)
	}

	token.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	currentToken = &token

	log.Printf("Successfully authenticated with Bitwarden API")
	return nil
}

func generateDeviceIdentifier() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		hostname, _ := os.Hostname()
		return fmt.Sprintf("%s-%d", hostname, os.Getpid())
	}
	return hex.EncodeToString(bytes)
}

func testBitwardenAPI(config Configuration) error {
	req, err := http.NewRequest("GET", config.APIBaseURL+"/public/events", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+currentToken.AccessToken)
	req.Header.Set("User-Agent", "Bitwarden-Event-Forwarder/2.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API test returned status %d", resp.StatusCode)
	}

	return nil
}

func testConfigFiles(config Configuration) error {
	if _, err := os.Stat(config.FieldMapFile); os.IsNotExist(err) {
		defaultMapping := createDefaultFieldMapping()
		if err := saveFieldMapping(config.FieldMapFile, defaultMapping); err != nil {
			return fmt.Errorf("failed to create default field mapping: %w", err)
		}
		log.Printf("📋 Created default field mapping file: %s", config.FieldMapFile)
	}

	if _, err := os.Stat(config.EventMapFile); os.IsNotExist(err) {
		return fmt.Errorf("event mapping file not found: %s (please provide bitwarden_event_map.json)", config.EventMapFile)
	}

	return nil
}

func testFilePermissions(config Configuration) error {
	dir := filepath.Dir(config.MarkerFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create marker file directory: %w", err)
	}

	testFile := filepath.Join(dir, "test_permissions")
	if err := ioutil.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("cannot write to marker file directory: %w", err)
	}
	os.Remove(testFile)

	return nil
}

func getEventDeduplicationKey(event BitwardenEvent) string {
	// Create a composite key from event properties since Bitwarden events have no ID
	var keyParts []string
	
	// Always include type, date (to the second), and device
	keyParts = append(keyParts, fmt.Sprintf("t%d", event.Type))
	keyParts = append(keyParts, fmt.Sprintf("d%d", event.Date.Unix()))
	keyParts = append(keyParts, fmt.Sprintf("dev%d", event.Device))
	
	// Add optional fields if present
	if event.ActingUserID != nil {
		keyParts = append(keyParts, fmt.Sprintf("au%s", *event.ActingUserID))
	}
	if event.MemberID != nil {
		keyParts = append(keyParts, fmt.Sprintf("m%s", *event.MemberID))
	}
	if event.ItemID != nil {
		keyParts = append(keyParts, fmt.Sprintf("i%s", *event.ItemID))
	}
	if event.GroupID != nil {
		keyParts = append(keyParts, fmt.Sprintf("g%s", *event.GroupID))
	}
	if event.CollectionID != nil {
		keyParts = append(keyParts, fmt.Sprintf("c%s", *event.CollectionID))
	}
	if event.PolicyID != nil {
		keyParts = append(keyParts, fmt.Sprintf("p%s", *event.PolicyID))
	}
	if event.IPAddress != nil {
		keyParts = append(keyParts, fmt.Sprintf("ip%s", *event.IPAddress))
	}
	
	return strings.Join(keyParts, "|")
}

func startHealthCheckServer(port int) {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		serviceStats.RLock()
		
		// Get cache stats if available
		var cacheStats EventCacheStats
		if eventCache != nil {
			cacheStats = eventCache.GetStats()
		}
		
		status := map[string]interface{}{
			"status":                      "healthy",
			"uptime":                      time.Since(serviceStats.StartTime).String(),
			"last_successful_run":         serviceStats.LastSuccessfulRun.Format(time.RFC3339),
			"total_events":                serviceStats.TotalEventsForwarded,
			"total_filtered":              serviceStats.TotalEventsFiltered,
			"total_dropped":               serviceStats.TotalEventsDropped,
			"total_api_requests":          serviceStats.TotalAPIRequests,
			"failed_api_requests":         serviceStats.FailedAPIRequests,
			"retry_attempts":              serviceStats.TotalRetryAttempts,
			"successful_recoveries":       serviceStats.SuccessfulRecoveries,
			"syslog_reconnects":           serviceStats.SyslogReconnects,
			"cache_hits":                  serviceStats.CacheHits,
			"cache_misses":                serviceStats.CacheMisses,
			"lookup_failures":             serviceStats.LookupFailures,
			"change_detection_events":     serviceStats.ChangeDetectionEvents,
			"marker_file_updates":         serviceStats.MarkerFileUpdates,
			"last_error":                  serviceStats.LastError,
			"last_error_time":             serviceStats.LastErrorTime.Format(time.RFC3339),
			"average_events_per_second":   serviceStats.AverageEventsPerSecond,
			"event_cache": map[string]interface{}{
				"duplicates_detected": cacheStats.DuplicatesDetected,
				"cache_hits":         cacheStats.CacheHits,
				"cache_misses":       cacheStats.CacheMisses,
				"cache_size":         cacheStats.CacheSize,
			},
		}
		serviceStats.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		serviceStats.RLock()
		fmt.Fprintf(w, "bitwarden_forwarder_uptime_seconds %d\n", int64(time.Since(serviceStats.StartTime).Seconds()))
		fmt.Fprintf(w, "bitwarden_forwarder_total_events %d\n", serviceStats.TotalEventsForwarded)
		fmt.Fprintf(w, "bitwarden_forwarder_total_filtered %d\n", serviceStats.TotalEventsFiltered)
		fmt.Fprintf(w, "bitwarden_forwarder_total_dropped %d\n", serviceStats.TotalEventsDropped)
		fmt.Fprintf(w, "bitwarden_forwarder_api_requests_total %d\n", serviceStats.TotalAPIRequests)
		fmt.Fprintf(w, "bitwarden_forwarder_api_requests_failed %d\n", serviceStats.FailedAPIRequests)
		fmt.Fprintf(w, "bitwarden_forwarder_syslog_reconnects %d\n", serviceStats.SyslogReconnects)
		fmt.Fprintf(w, "bitwarden_forwarder_cache_hits %d\n", serviceStats.CacheHits)
		fmt.Fprintf(w, "bitwarden_forwarder_cache_misses %d\n", serviceStats.CacheMisses)
		serviceStats.RUnlock()
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("❌ Health check server error: %v", err)
	}
}

func processEventsWithRecovery(config Configuration, fieldMapping FieldMapping, syslogWriter *SyslogWriter, marker TimeBasedMarker) TimeBasedMarker {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("🚨 PANIC recovered in processEvents: %v", r)
			serviceStats.Lock()
			serviceStats.LastError = fmt.Sprintf("PANIC: %v", r)
			serviceStats.LastErrorTime = time.Now()
			serviceStats.Unlock()
		}
	}()

	newMarker, err := processAllEventsWithStats(config, fieldMapping, syslogWriter, marker)
	if err != nil {
		log.Printf("❌ Error processing events: %v", err)
		serviceStats.Lock()
		serviceStats.LastError = err.Error()
		serviceStats.LastErrorTime = time.Now()
		serviceStats.FailedAPIRequests++
		serviceStats.Unlock()
		
		// Return marker with updated poll count even on failure
		newMarker = marker
		newMarker.PollCount++
	}

	return newMarker
}

func processAllEventsWithStats(config Configuration, fieldMapping FieldMapping, syslogWriter *SyslogWriter, marker TimeBasedMarker) (TimeBasedMarker, error) {
	pollStart := time.Now()
	
	totalEventsProcessed := 0
	totalEventsFiltered := 0
	totalEventsDropped := 0
	totalDuplicates := 0
	numErrors := 0
	totalRetryErrors := 0
	recoveries := 0
	cacheHits := 0
	cacheMisses := 0
	lookupFailures := 0
	changeDetectionEvents := 0
	
	serviceStats.Lock()
	serviceStats.TotalAPIRequests++
	serviceStats.Unlock()
	
	events, newMarker, err := fetchBitwardenEventsWithRetry(config, marker, &totalRetryErrors, &recoveries)
	if err != nil {
		numErrors++
		log.Printf("❌ Error fetching events: %v", err)
		return marker, err
	}
	
	pollEnd := time.Now()
	
	if len(events) > 0 {
		// Use enhanced filtering with deduplication
		filteredEvents, droppedCount, duplicateCount, eventCacheHits, eventCacheMisses := filterEventsWithDeduplication(events, fieldMapping.EventFiltering, fieldMapping.Statistics)
		totalEventsFiltered += droppedCount
		totalDuplicates += duplicateCount
		
		if len(filteredEvents) > 0 {
			forwarded, dropped, _, lookupStats, changeStats, err := forwardEventsWithStats(
				filteredEvents, config, fieldMapping, syslogWriter)
			
			if err != nil {
				numErrors++
				log.Printf("❌ Error forwarding events: %v", err)
				return marker, err
			}
			
			totalEventsProcessed += forwarded
			totalEventsDropped += dropped
			lookupFailures += lookupStats.Failures
			changeDetectionEvents += changeStats.ChangeEvents
		}
		
		// Track event cache stats separately from lookup cache stats
		cacheHits += eventCacheHits
		cacheMisses += eventCacheMisses
	}
	
	// Save the new marker
	if err := saveTimeBasedMarker(config.MarkerFile, newMarker); err != nil {
		log.Printf("⚠️  Warning: Error saving marker file: %v", err)
	} else {
		serviceStats.Lock()
		serviceStats.MarkerFileUpdates++
		serviceStats.Unlock()
	}
	
	var periodStart, periodEnd int64
	if len(events) > 0 {
		// Use the time range of the actual events fetched
		firstEvent := events[0]
		lastEvent := events[len(events)-1]
		periodStart = firstEvent.Date.Unix()
		periodEnd = lastEvent.Date.Unix()
	} else {
		// No events - use the API query window
		var startTime time.Time
		if marker.PollCount == 0 {
			startTime = pollStart.Add(-time.Duration(config.InitialLookbackHours) * time.Hour)
		} else {
			startTime = marker.LastEventTime.Add(-1 * time.Minute)
		}
		periodStart = startTime.Unix()
		periodEnd = pollEnd.Unix()
	}
	
	var eventsPerSecond float64
	if pollEnd.After(pollStart) && totalEventsProcessed > 0 {
		duration := pollEnd.Sub(pollStart).Seconds()
		eventsPerSecond = float64(totalEventsProcessed) / duration
		
		serviceStats.Lock()
		serviceStats.CurrentPollDuration = pollEnd.Sub(pollStart)
		serviceStats.AverageEventsPerSecond = eventsPerSecond
		serviceStats.LastSuccessfulRun = pollEnd
		serviceStats.TotalEventsForwarded += int64(totalEventsProcessed)
		serviceStats.TotalEventsFiltered += int64(totalEventsFiltered)
		serviceStats.TotalEventsDropped += int64(totalEventsDropped)
		serviceStats.CacheHits += int64(cacheHits)
		serviceStats.CacheMisses += int64(cacheMisses)
		serviceStats.LookupFailures += int64(lookupFailures)
		serviceStats.ChangeDetectionEvents += int64(changeDetectionEvents)
		serviceStats.TotalRetryAttempts += int64(totalRetryErrors)
		serviceStats.SuccessfulRecoveries += int64(recoveries)
		serviceStats.Unlock()
	}
	
	log.Printf("📊 Time-Based Poll #%d Summary [%d - %d]: Events=%d, Duplicates=%d, Filtered=%d, Forwarded=%d, Dropped=%d, "+
		"Rate=%.2f events/sec, Errors=%d, Retries=%d, Recoveries=%d, EventCache H/M=%d/%d, "+
		"Next Poll From=%s",
		newMarker.PollCount, periodStart, periodEnd,
		len(events), totalDuplicates, totalEventsFiltered,
		totalEventsProcessed, totalEventsDropped, eventsPerSecond, numErrors, totalRetryErrors,
		recoveries, cacheHits, cacheMisses,
		newMarker.LastEventTime.Add(-time.Duration(config.PollOverlapMinutes) * time.Minute).Format("2006-01-02T15:04:05"))	
	return newMarker, nil
}

func fetchBitwardenEventsWithRetry(config Configuration, marker TimeBasedMarker, totalRetryErrors *int, recoveries *int) ([]BitwardenEvent, TimeBasedMarker, error) {
	var lastErr error
	
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(config.RetryDelay) * time.Second
			log.Printf("🔄 Retry attempt %d/%d after %v", attempt, config.MaxRetries, delay)
			time.Sleep(delay)
		}
		
		events, newMarker, err := fetchBitwardenEvents(config, marker)
		if err == nil {
			if attempt > 0 {
				*recoveries++
			}
			return events, newMarker, nil
		}
		
		*totalRetryErrors++
		lastErr = err
		log.Printf("❌ API request attempt %d failed: %v", attempt+1, err)
	}
	
	return nil, marker, fmt.Errorf("all retry attempts failed, last error: %w", lastErr)
}

func fetchBitwardenEvents(config Configuration, marker TimeBasedMarker) ([]BitwardenEvent, TimeBasedMarker, error) {
	if currentToken == nil || time.Now().After(currentToken.ExpiresAt.Add(-5*time.Minute)) {
		if err := authenticateWithBitwarden(config); err != nil {
			return nil, marker, fmt.Errorf("token refresh failed: %w", err)
		}
	}
	
	// FIXED: Proper sliding window calculation
	var startTime time.Time
	endTime := time.Now()
	
	if marker.LastEventTime.IsZero() || marker.PollCount == 0 {
		// First poll: Use initial lookback
		startTime = endTime.Add(-time.Duration(config.InitialLookbackHours) * time.Hour)
	} else {
		// Subsequent polls: Use configured overlap minutes
		overlapDuration := time.Duration(config.PollOverlapMinutes) * time.Minute
		startTime = marker.LastEventTime.Add(-overlapDuration)
	}
	
	// Build URL with time parameters (IGNORE continuationToken completely)
	url := fmt.Sprintf("%s/public/events?start=%s&end=%s", 
		config.APIBaseURL,
		startTime.Format(time.RFC3339),
		endTime.Format(time.RFC3339))
	
		if config.Verbose {
			overlapStr := fmt.Sprintf("%dm", config.PollOverlapMinutes)
			if marker.PollCount == 0 {
				overlapStr = fmt.Sprintf("%dh", config.InitialLookbackHours)
			}
			log.Printf("🔍 Fetching events: Start=%s, End=%s (overlap=%s)", 
				startTime.Format("2006-01-02T15:04:05"), 
				endTime.Format("2006-01-02T15:04:05"),
				overlapStr)
		}
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, marker, fmt.Errorf("error creating request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+currentToken.AccessToken)
	req.Header.Set("User-Agent", "Bitwarden-Event-Forwarder/2.0")
	
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, marker, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, marker, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}
	
	var response BitwardenEventsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, marker, fmt.Errorf("error parsing JSON response: %w", err)
	}
	
	if config.Verbose {
		log.Printf("🔍 Raw API response: EventCount=%d (ignoring continuationToken)", len(response.Data))
	}
	
	// Sort events by date to ensure proper ordering
	sort.Slice(response.Data, func(i, j int) bool {
		return response.Data[i].Date.Before(response.Data[j].Date)
	})
	
	// FIXED: Update marker with the current poll's endTime (becomes next poll's reference point)
	newMarker := TimeBasedMarker{
		LastEventTime: endTime,  // CRITICAL: Always use endTime so next poll can calculate properly
		LastEventID:   "",       // Optional: could store latest event ID for reference
		PollCount:     marker.PollCount + 1,
	}
	
	// Optional: Store a reference to the newest event for debugging
	if len(response.Data) > 0 {
		newestEvent := response.Data[len(response.Data)-1]
		newMarker.LastEventID = getEventDeduplicationKey(newestEvent)
	}
	
	return response.Data, newMarker, nil
}

func shouldProcessEvent(event BitwardenEvent, eventType string, filter EventFilter) bool {
	for _, priority := range filter.PriorityEvents {
		if eventType == priority {
			return true
		}
	}
	
	if !passesUserFilter(event, filter.UserFiltering) {
		return false
	}
	
	if !passesRateLimit(eventType, filter.RateLimiting) {
		return false
	}
	
	switch filter.Mode {
	case "include":
		if len(filter.IncludedEvents) == 0 {
			return true
		}
		for _, included := range filter.IncludedEvents {
			if eventType == included {
				return true
			}
		}
		return false
		
	case "exclude":
		for _, excluded := range filter.ExcludedEvents {
			if eventType == excluded {
				return false
			}
		}
		return true
		
	default:
		return true
	}
}

func passesRateLimit(eventType string, rateLimits map[string]RateLimit) bool {
	limit, exists := rateLimits[eventType]
	if !exists || !limit.Enabled {
		return true
	}
	
	rateLimitTracker.Lock()
	defer rateLimitTracker.Unlock()
	
	now := time.Now()
	hourAgo := now.Add(-time.Hour)
	
	var recentEvents []time.Time
	if timestamps, exists := rateLimitTracker.EventCounts[eventType]; exists {
		for _, timestamp := range timestamps {
			if timestamp.After(hourAgo) {
				recentEvents = append(recentEvents, timestamp)
			}
		}
	}
	
	if len(recentEvents) >= limit.MaxPerHour {
		return false
	}
	
	recentEvents = append(recentEvents, now)
	rateLimitTracker.EventCounts[eventType] = recentEvents
	
	return true
}

func passesUserFilter(event BitwardenEvent, userFilter UserFilter) bool {
	if userFilter.ExcludeServiceAccounts && isServiceAccount(event) {
		return false
	}
	
	if len(userFilter.IncludeOnlyUsers) > 0 {
		userID := getUserIDFromEvent(event)
		for _, user := range userFilter.IncludeOnlyUsers {
			if userID == user {
				return true
			}
		}
		return false
	}
	
	userID := getUserIDFromEvent(event)
	for _, user := range userFilter.ExcludeUsers {
		if userID == user {
			return false
		}
	}
	
	return true
}

func getUserIDFromEvent(event BitwardenEvent) string {
	if event.MemberID != nil {
		return *event.MemberID
	}
	return ""
}

func isServiceAccount(event BitwardenEvent) bool {
	return false
}

// REPLACE your existing forwardEventsWithStats function with this version:

func forwardEventsWithStats(events []BitwardenEvent, config Configuration, 
	fieldMapping FieldMapping, syslogWriter *SyslogWriter) (int, int, CacheStats, LookupStats, ChangeStats, error) {
	
	var forwarded, dropped int
	var cacheStats CacheStats
	var lookupStats LookupStats
	var changeStats ChangeStats
	
	for _, event := range events {
		// Declare eventKey at the beginning of the loop so it's available throughout
		eventKey := getEventDeduplicationKey(event)
		
		enrichedEvent, cacheHit, lookupSuccess := enrichEvent(event, fieldMapping, config)
		
		if cacheHit {
			cacheStats.Hits++
		} else {
			cacheStats.Misses++
		}
		
		if !lookupSuccess {
			lookupStats.Failures++
		} else {
			lookupStats.Success++
		}
		
		cefMessage := formatEventAsCEF(enrichedEvent, config, fieldMapping)
		syslogMessage := formatSyslogMessage("bitwarden-forwarder", cefMessage)
		
		if len(syslogMessage) > config.MaxMsgSize {
			syslogMessage = syslogMessage[:config.MaxMsgSize]
		}
		
		if err := syslogWriter.Write(syslogMessage); err != nil {
			log.Printf("🔄 Syslog write failed, attempting reconnect: %v", err)
			if reconnectErr := syslogWriter.Reconnect(); reconnectErr != nil {
				return forwarded, dropped, cacheStats, lookupStats, changeStats, fmt.Errorf("reconnection failed: %w", reconnectErr)
			}
			
			if err = syslogWriter.Write(syslogMessage); err != nil {
				dropped++
				log.Printf("❌ Failed to forward event Key=%s after reconnect: %v", eventKey, err)
				continue
			}
		}
		
		// ONLY mark as processed AFTER successful forwarding
		if eventCache != nil {
			eventCache.MarkProcessed(eventKey)
			log.Printf("✅ MARKED PROCESSED: Key=%s, Type=%s, EventTime=%s, ProcessedAt=%s", 
				eventKey, fmt.Sprintf("%d", event.Type), 
				event.Date.Format("2006-01-02T15:04:05"),
				time.Now().Format("2006-01-02T15:04:05"))
		}
			
		forwarded++
	}
	
	return forwarded, dropped, cacheStats, lookupStats, changeStats, nil
}

func enrichEvent(event BitwardenEvent, fieldMapping FieldMapping, config Configuration) (map[string]interface{}, bool, bool) {
	eventKey := getEventDeduplicationKey(event)
	enriched := map[string]interface{}{
		"eventKey": eventKey,
		"type":   event.Type,
		"date":   event.Date.Format(time.RFC3339),
		"device": event.Device,
		"object": event.Object,
	}
	
	if event.MemberID != nil {
		enriched["memberId"] = *event.MemberID
	}
	if event.ActingUserID != nil {
		enriched["actingUserId"] = *event.ActingUserID
	}
	if event.GroupID != nil {
		enriched["groupId"] = *event.GroupID
	}
	if event.CollectionID != nil {
		enriched["collectionId"] = *event.CollectionID
	}
	if event.PolicyID != nil {
		enriched["policyId"] = *event.PolicyID
	}
	if event.ItemID != nil {
		enriched["itemId"] = *event.ItemID
	}
	if event.InstallationID != nil {
		enriched["installationId"] = *event.InstallationID
	}
	if event.IPAddress != nil {
		enriched["ipAddress"] = *event.IPAddress
	}
	
	if eventName, exists := eventTypeMap[fmt.Sprintf("%d", event.Type)]; exists {
		enriched["eventTypeName"] = eventName
	}
	enriched["deviceTypeName"] = getDeviceTypeName(event.Device)
	
	return enriched, true, true
}

func getDeviceTypeName(deviceType int) string {
	deviceNames := map[int]string{
		0: "Android", 1: "iOS", 2: "Chrome Extension", 3: "Firefox Extension",
		4: "Opera Extension", 5: "Edge Extension", 6: "Windows Desktop", 7: "macOS Desktop",
		8: "Linux Desktop", 9: "Chrome App", 10: "Vivaldi", 11: "Safari",
		12: "UWP", 13: "Bitwarden", 14: "Directory Connector", 15: "Azure AD Connector",
		16: "Okta Connector", 17: "OneLogin Connector", 18: "CLI", 19: "Connector",
		20: "SCIM", 21: "SDK", 22: "Server", 23: "Windows CLI", 24: "macOS CLI", 25: "Linux CLI",
	}
	
	if name, exists := deviceNames[deviceType]; exists {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", deviceType)
}

func formatEventAsCEF(event map[string]interface{}, config Configuration, fieldMapping FieldMapping) string {
	eventType := fmt.Sprintf("%v", event["type"])
	eventName := "Unknown Event"
	
	if name, exists := eventTypeMap[eventType]; exists {
		eventName = name
	}
	
	severity := mapEventTypeToSeverity(eventType)
	
	vendor := fieldMapping.CEFVendor
	if vendor == "" {
		vendor = "Bitwarden"
	}
	product := fieldMapping.CEFProduct
	if product == "" {
		product = "Events"
	}
	version := fieldMapping.CEFVersion
	if version == "" {
		version = "1.0"
	}
	
	header := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|",
		vendor, product, version, eventType, eventName, severity)
	
	extensions := make(map[string]string)
	
	for sourceKey, targetKey := range fieldMapping.FieldMappings {
		if value, exists := event[sourceKey]; exists && value != nil {
			extensions[targetKey] = sanitizeCEFValue(fmt.Sprintf("%v", value))
		}
	}
	
	for k, v := range event {
		if !isMappedField(k, fieldMapping.FieldMappings) && v != nil {
			extensions[k] = sanitizeCEFValue(fmt.Sprintf("%v", v))
		}
	}
	
	var parts []string
	
	for _, field := range fieldMapping.OrderedFields {
		if value, exists := extensions[field]; exists {
			parts = append(parts, fmt.Sprintf("%s=%s", field, value))
			delete(extensions, field)
		}
	}
	
	var remaining []string
	for k := range extensions {
		remaining = append(remaining, k)
	}
	sort.Strings(remaining)
	
	for _, field := range remaining {
		parts = append(parts, fmt.Sprintf("%s=%s", field, extensions[field]))
	}
	
	return header + strings.Join(parts, " ")
}

func mapEventTypeToSeverity(eventType string) int {
	severityMap := map[string]int{
		"1000": 6, "1001": 6, "1002": 6, "1005": 8, "1006": 8,
		"1500": 6, "1501": 6, "1502": 6, "1503": 7, "1700": 7, "1600": 7,
	}
	
	if severity, exists := severityMap[eventType]; exists {
		return severity
	}
	return 5
}

func sanitizeCEFValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "=", "\\=")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\r", "\\r")
	return value
}

func formatSyslogMessage(hostname, message string) string {
	priority := "134"
	timestamp := time.Now().Format("Jan _2 15:04:05")
	return fmt.Sprintf("<%s>%s %s %s", priority, timestamp, hostname, message)
}

func isMappedField(fieldName string, fieldMappings map[string]string) bool {
	_, exists := fieldMappings[fieldName]
	return exists
}

func loadFieldMapping(filename string) FieldMapping {
	defaultMapping := createDefaultFieldMapping()
	
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("📋 Creating default field mapping file: %s", filename)
			saveFieldMapping(filename, defaultMapping)
		}
		return defaultMapping
	}
	
	var mapping FieldMapping
	if err := json.Unmarshal(data, &mapping); err != nil {
		log.Printf("❌ Error parsing field mapping file: %v, using defaults", err)
		return defaultMapping
	}
	
	return mapping
}

func loadEventTypeMap(filename string) map[string]string {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("❌ Event type mapping file not found: %s", filename)
			log.Printf("📝 Please ensure bitwarden_event_map.json exists")
			return make(map[string]string)
		}
		log.Printf("❌ Error reading event type mapping file: %v", err)
		return make(map[string]string)
	}
	
	var eventMap map[string]string
	if err := json.Unmarshal(data, &eventMap); err != nil {
		log.Printf("❌ Error parsing event type mapping file: %v", err)
		return make(map[string]string)
	}
	
	return eventMap
}

func createDefaultFieldMapping() FieldMapping {
	return FieldMapping{
		OrderedFields: []string{
			"rt", "cs1", "cs2", "suser", "email", "status", "2fa", "host_ip",
			"device", "groupId", "collectionId", "policyId", "actingUserId",
			"objectname", "community", "roles", "caseName", "hasDataChanges",
			"changeType", "changeCount", "changedFields", "oldValues", "newValues",
		},
		FieldMappings: map[string]string{
			"date": "rt", "type": "cs1", "id": "cs2", "memberId": "suser",
			"actingUserId": "actingUserId", "ipAddress": "host_ip", "device": "device",
			"groupId": "groupId", "collectionId": "collectionId", "policyId": "policyId", "object": "objectname",
		},
		Lookups: map[string]LookupConfig{
			"memberId": {
				Endpoint: "/public/members/{id}",
				ResponseMapping: map[string]string{
					"name": "memberName", "email": "memberEmail", "status": "memberStatus",
					"twoFactorEnabled": "member2FA", "type": "memberType", "accessAll": "memberAccessAll",
					"externalId": "memberExternalId", "resetPasswordEnrolled": "memberResetPasswordEnrolled",
				},
			},
		},
		CacheInvalidationRules: map[string][]string{
			"1700": {"policyId"}, "1500": {"memberId"}, "1501": {"memberId"}, "1502": {"memberId"},
			"1503": {"memberId"}, "1504": {"memberId"}, "1505": {"memberId"},
			"1400": {"groupId"}, "1401": {"groupId"}, "1402": {"groupId"},
			"1300": {"collectionId"}, "1301": {"collectionId"}, "1302": {"collectionId"},
		},
		EventFiltering: EventFilter{
			Mode: "exclude",
			ExcludedEvents: []string{"1114", "1107", "1108", "1109", "1110", "1111", "1112", "1113", "1117"},
			IncludedEvents: []string{},
			RateLimiting: map[string]RateLimit{
				"1114": {MaxPerHour: 10, Enabled: true},
				"1107": {MaxPerHour: 50, Enabled: true},
				"1111": {MaxPerHour: 20, Enabled: true},
			},
			PriorityEvents: []string{"1000", "1001", "1002", "1005", "1006", "1500", "1501", "1502", "1503", "1700", "1600", "1601"},
			UserFiltering: UserFilter{ExcludeServiceAccounts: true, ExcludeUsers: []string{}, IncludeOnlyUsers: []string{}},
		},
		Statistics: StatisticsConfig{
			EnableDetailedLogging: true, LogIntervalEvents: 100,
			TrackCacheMetrics: true, TrackPerformanceMetrics: true,
		},
		CEFVendor: "Bitwarden", CEFProduct: "Events", CEFVersion: "1.0",
	}
}

func saveFieldMapping(filename string, mapping FieldMapping) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	data, err := json.MarshalIndent(mapping, "", "  ")
	if err != nil {
		return err
	}
	
	return ioutil.WriteFile(filename, data, 0644)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvOrIntDefault(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		var result int
		if _, err := fmt.Sscanf(value, "%d", &result); err == nil {
			return result
		}
	}
	return defaultValue
}

func getEnvOrBoolDefault(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		switch strings.ToLower(value) {
		case "true", "1", "yes", "y", "on":
			return true
		case "false", "0", "no", "n", "off":
			return false
		}
	}
	return defaultValue
}

// Event Cache Functions
func NewEventCache(maxSize int, windowDuration time.Duration) *EventCache {
	return &EventCache{
		processedEvents: make(map[string]time.Time),
		eventRing:       ring.New(maxSize),
		maxCacheSize:    maxSize,
		cacheWindow:     windowDuration,
	}
}

func (ec *EventCache) HasProcessed(eventID string) bool {
	ec.RLock()
	defer ec.RUnlock()
	_, exists := ec.processedEvents[eventID]
	return exists
}

func (ec *EventCache) MarkProcessed(eventID string) {
	ec.Lock()
	defer ec.Unlock()
	
	now := time.Now()
	if len(ec.processedEvents) >= ec.maxCacheSize {
		if ec.eventRing.Value != nil {
			if oldestID, ok := ec.eventRing.Value.(string); ok {
				delete(ec.processedEvents, oldestID)
			}
		}
	}
	
	ec.processedEvents[eventID] = now
	ec.eventRing.Value = eventID
	ec.eventRing = ec.eventRing.Next()
}

func (ec *EventCache) GetStats() EventCacheStats {
	ec.RLock()
	defer ec.RUnlock()
	
	return EventCacheStats{
		DuplicatesDetected: eventCacheStats.DuplicatesDetected,
		CacheHits:          eventCacheStats.CacheHits,
		CacheMisses:        eventCacheStats.CacheMisses,
		CacheSize:          len(ec.processedEvents),
	}
}

func (ec *EventCache) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ec.Lock()
			now := time.Now()
			cutoff := now.Add(-ec.cacheWindow)
			
			for eventID, timestamp := range ec.processedEvents {
				if timestamp.Before(cutoff) {
					delete(ec.processedEvents, eventID)
				}
			}
			ec.Unlock()
			
		case <-ctx.Done():
			return
		}
	}
}

// Time-based Marker Functions
func loadTimeBasedMarker(filename string) TimeBasedMarker {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("⚠️  Error reading marker file %s: %v", filename, err)
		}
		return TimeBasedMarker{
			LastEventTime: time.Now().Add(-24 * time.Hour),
			LastEventID:   "",
			PollCount:     0,
		}
	}
	
	var marker TimeBasedMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		log.Printf("⚠️  Error parsing marker file, using defaults: %v", err)
		return TimeBasedMarker{
			LastEventTime: time.Now().Add(-24 * time.Hour),
			LastEventID:   "",
			PollCount:     0,
		}
	}
	
	log.Printf("📍 Loaded time-based marker: LastEventTime=%s, PollCount=%d", 
		marker.LastEventTime.Format(time.RFC3339), marker.PollCount)
	
	return marker
}

func saveTimeBasedMarker(filename string, marker TimeBasedMarker) error {
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal marker: %w", err)
	}
	
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for marker file: %w", err)
	}
	
	return ioutil.WriteFile(filename, data, 0644)
}

// Enhanced Filtering with Deduplication
func filterEventsWithDeduplication(events []BitwardenEvent, filter EventFilter, stats StatisticsConfig) ([]BitwardenEvent, int, int, int, int) {
	if filter.Mode == "all" && eventCache == nil {
		return events, 0, 0, 0, 0
	}
	
	var filteredEvents []BitwardenEvent
	droppedCount := 0
	duplicateCount := 0
	localCacheHits := 0
	localCacheMisses := 0
	
	for _, event := range events {
		eventType := fmt.Sprintf("%d", event.Type)
		eventKey := getEventDeduplicationKey(event)
		
		if eventCache != nil {
			if eventCache.HasProcessed(eventKey) {
				// CACHE HIT - it's a duplicate
				duplicateCount++
				eventCacheStats.DuplicatesDetected++
				eventCacheStats.CacheHits++
				localCacheHits++
				
				eventCache.RLock()
				processedTime, exists := eventCache.processedEvents[eventKey]
				eventCache.RUnlock()
				
				if exists {
					log.Printf("🔄 DUPLICATE: Key=%s, Type=%s, EventTime=%s, FirstProcessed=%s, Age=%v", 
						eventKey, eventType, 
						event.Date.Format("2006-01-02T15:04:05"),
						processedTime.Format("2006-01-02T15:04:05"),
						time.Since(processedTime))
				}
				continue
			} else {
				// CACHE MISS - it's a new event
				eventCacheStats.CacheMisses++
				localCacheMisses++
			}
		}
		
		// Apply existing filtering logic
		if shouldProcessEvent(event, eventType, filter) {
			filteredEvents = append(filteredEvents, event)
		} else {
			droppedCount++
			if stats.EnableDetailedLogging {
				log.Printf("🚫 Filtered event type %s (Key: %s)", eventType, eventKey)
			}
		}
	}
	
	return filteredEvents, droppedCount, duplicateCount, localCacheHits, localCacheMisses
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
