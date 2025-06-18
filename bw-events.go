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

type JSONConfig struct {
	BitwardenAPI BitwardenAPIConfig `json:"bitwarden_api"`
	Syslog       SyslogConfig       `json:"syslog"`
	Polling      PollingConfig      `json:"polling"`
	Logging      LoggingConfig      `json:"logging"`
	Files        FilesConfig        `json:"files"`
	Monitoring   MonitoringConfig   `json:"monitoring"`
	EventFilter  *EventFilter       `json:"event_filtering,omitempty"`
	Statistics   *StatisticsConfig  `json:"statistics,omitempty"`
}

type BitwardenAPIConfig struct {
	APIBaseURL   string `json:"api_base_url"`
	IdentityURL  string `json:"identity_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type SyslogConfig struct {
	Server   string `json:"server"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type PollingConfig struct {
	FetchInterval         int `json:"fetch_interval"`
	ConnectionTimeout     int `json:"connection_timeout"`
	MaxRetries           int `json:"max_retries"`
	RetryDelay           int `json:"retry_delay"`
	MaxBackoffDelay      int `json:"max_backoff_delay"`
	InitialLookbackHours int `json:"initial_lookback_hours"`
	PollOverlapMinutes   int `json:"poll_overlap_minutes"`
	MaxEventsPerPoll     int `json:"max_events_per_poll"`
}

type LoggingConfig struct {
	LogLevel string `json:"log_level"`
	LogFile  string `json:"log_file"`
	Verbose  bool   `json:"verbose"`
}

type FilesConfig struct {
	MarkerFile    string `json:"marker_file"`
	FieldMapFile  string `json:"field_map_file"`
	EventMapFile  string `json:"event_map_file"`
}

type MonitoringConfig struct {
	HealthCheckPort  int  `json:"health_check_port"`
	EnableMetrics    bool `json:"enable_metrics"`
	MaxMsgSize       int  `json:"max_msg_size"`
	EventCacheSize   int  `json:"event_cache_size"`
	EventCacheWindow int  `json:"event_cache_window"`
	EnableEventCache bool `json:"enable_event_cache"`
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
	CollectionID *string   `json:"collectionId,omitempty"`
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

// Updated global cache - index by BOTH userId AND orgMemberId
var memberListCache struct {
	sync.RWMutex
	membersByUserId  map[string]map[string]interface{} // userId -> member data
	membersByOrgId   map[string]map[string]interface{} // orgMemberID -> member data
	lastUpdate       time.Time
	ttl              time.Duration
	missedLookups    map[string]time.Time              // Track failed lookups to trigger refresh
}

func printUsage() {
	fmt.Println("Bitwarden Event Forwarder v2.0.0")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  bw-events [options]")
	fmt.Println()
	fmt.Println("Configuration:")
	fmt.Println("  --config FILE              Load configuration from JSON file")
	fmt.Println("  --generate-config FILE     Generate a sample configuration file")
	fmt.Println("  --validate                 Validate configuration and exit")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Generate sample config")
	fmt.Println("  ./bw-events --generate-config /etc/bitwarden/config.json")
	fmt.Println()
	fmt.Println("  # Validate config file")
	fmt.Println("  ./bw-events --validate --config /etc/bitwarden/config.json")
	fmt.Println()
	fmt.Println("  # Run with config file")
	fmt.Println("  ./bw-events --config /etc/bitwarden/config.json")
	fmt.Println()
	fmt.Println("  # Override config file settings with CLI args")
	fmt.Println("  ./bw-events --config /etc/bitwarden/config.json --verbose --log-level debug")
	fmt.Println()
}

func main() {
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	config := loadConfig()

	for i, arg := range os.Args[1:] {
		if arg == "--generate-config" && i+1 < len(os.Args)-1 {
			configPath := os.Args[i+2]
			log.Printf("📋 Generating sample configuration file: %s", configPath)
			if err := createSampleConfigFile(configPath); err != nil {
				log.Fatalf("❌ Failed to generate config file: %v", err)
			}
			log.Printf("✅ Sample configuration file created: %s", configPath)
			log.Println("📝 Please edit the file with your actual credentials and settings")
			return
		}
	}

	if config.ShowVersion {
		fmt.Println("Bitwarden Event Forwarder v2.0.0 - Enhanced with Filtering & Statistics")
		return
	}

	if config.ValidateMode {
		// Check if we're validating a specific config file
		configFileProvided := false
		for i, arg := range os.Args[1:] {
			if arg == "--config" && i+1 < len(os.Args)-1 {
				configFilePath := os.Args[i+2]
				if err := validateConfigFile(configFilePath); err != nil {
					log.Fatalf("❌ Configuration file validation failed: %v", err)
				}
				configFileProvided = true
				break
			}
		}
		
		if !configFileProvided {
			// Validate the current configuration
			if err := validateConfig(config); err != nil {
				log.Fatalf("❌ Configuration validation failed: %v", err)
			}
			log.Println("✅ Configuration is valid")
		}
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

	// Add enhanced configuration logging
	if config.Verbose {
		logConfigurationSource(config)
	}

	// Use enhanced validation
	if err := validateConfigWithWarnings(config); err != nil {
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

	diagnoseUserMembership(config)

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
	configFile := flag.String("config", getEnvOrDefault("CONFIG_FILE", ""), "Load configuration from JSON file")
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
	generateConfig := flag.String("generate-config", "", "Generate a sample configuration file at the specified path")
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
	help := flag.Bool("help", false, "Show help message")

	flag.Parse()

	if *help {
		printUsage()
		os.Exit(0)
	}

	if *generateConfig != "" {
		log.Printf("📋 Generating sample configuration file: %s", *generateConfig)
		if err := createSampleConfigFile(*generateConfig); err != nil {
			log.Fatalf("❌ Failed to generate config file: %v", err)
		}
		log.Printf("✅ Sample configuration file created: %s", *generateConfig)
		log.Println("📝 Please edit the file with your actual credentials and settings")
		os.Exit(0)
	}

	// Start with defaults from command line and environment
	config := Configuration{
		APIBaseURL:           *apiURL,
		IdentityURL:          *identityURL,
		ClientID:             *clientID,
		ClientSecret:         *clientSecret,
		SyslogProtocol:       *syslogProto,
		SyslogServer:         *syslogServer,
		SyslogPort:           *syslogPort,
		LogLevel:             *logLevel,
		LogFile:              *logFile,
		FetchInterval:        *fetchInterval,
		ConnTimeout:          *connTimeout,
		MaxMsgSize:           *maxMsgSize,
		MarkerFile:           *markerFile,
		FieldMapFile:         *fieldMapFile,
		EventMapFile:         *eventMapFile,
		Verbose:              *verbose,
		MaxRetries:           *maxRetries,
		RetryDelay:           *retryDelay,
		HealthCheckPort:      *healthCheckPort,
		TestMode:             *testMode,
		ValidateMode:         *validateMode,
		ShowVersion:          *showVersion,
		EventCacheSize:       *eventCacheSize,
		EventCacheWindow:     *eventCacheWindow,
		EnableEventCache:     *enableEventCache,
		InitialLookbackHours: *initialLookback,
		PollOverlapMinutes:   *pollOverlap,
		MaxEventsPerPoll:     *maxEvents,
	}

	// Load from config file if specified
	if *configFile != "" {
		log.Printf("📋 Loading configuration from: %s", *configFile)
		
		if err := loadConfigFromFile(&config, *configFile); err != nil {
			log.Fatalf("❌ Failed to load config file: %v", err)
		}
		
		log.Printf("✅ Configuration loaded successfully from: %s", *configFile)
		
		// Command line arguments override config file values
		if flag.Lookup("api-url").Value.String() != flag.Lookup("api-url").DefValue {
			config.APIBaseURL = *apiURL
		}
		if flag.Lookup("identity-url").Value.String() != flag.Lookup("identity-url").DefValue {
			config.IdentityURL = *identityURL
		}
		if flag.Lookup("client-id").Value.String() != flag.Lookup("client-id").DefValue {
			config.ClientID = *clientID
		}
		if flag.Lookup("client-secret").Value.String() != flag.Lookup("client-secret").DefValue {
			config.ClientSecret = *clientSecret
		}
		if flag.Lookup("syslog-proto").Value.String() != flag.Lookup("syslog-proto").DefValue {
			config.SyslogProtocol = *syslogProto
		}
		if flag.Lookup("syslog-server").Value.String() != flag.Lookup("syslog-server").DefValue {
			config.SyslogServer = *syslogServer
		}
		if flag.Lookup("syslog-port").Value.String() != flag.Lookup("syslog-port").DefValue {
			config.SyslogPort = *syslogPort
		}
		if flag.Lookup("log-level").Value.String() != flag.Lookup("log-level").DefValue {
			config.LogLevel = *logLevel
		}
		if flag.Lookup("log-file").Value.String() != flag.Lookup("log-file").DefValue {
			config.LogFile = *logFile
		}
		if flag.Lookup("interval").Value.String() != flag.Lookup("interval").DefValue {
			config.FetchInterval = *fetchInterval
		}
		if flag.Lookup("conn-timeout").Value.String() != flag.Lookup("conn-timeout").DefValue {
			config.ConnTimeout = *connTimeout
		}
		if flag.Lookup("max-msg-size").Value.String() != flag.Lookup("max-msg-size").DefValue {
			config.MaxMsgSize = *maxMsgSize
		}
		if flag.Lookup("marker-file").Value.String() != flag.Lookup("marker-file").DefValue {
			config.MarkerFile = *markerFile
		}
		if flag.Lookup("field-map").Value.String() != flag.Lookup("field-map").DefValue {
			config.FieldMapFile = *fieldMapFile
		}
		if flag.Lookup("event-map").Value.String() != flag.Lookup("event-map").DefValue {
			config.EventMapFile = *eventMapFile
		}
		if flag.Lookup("verbose").Value.String() != flag.Lookup("verbose").DefValue {
			config.Verbose = *verbose
		}
		if flag.Lookup("max-retries").Value.String() != flag.Lookup("max-retries").DefValue {
			config.MaxRetries = *maxRetries
		}
		if flag.Lookup("retry-delay").Value.String() != flag.Lookup("retry-delay").DefValue {
			config.RetryDelay = *retryDelay
		}
		if flag.Lookup("health-port").Value.String() != flag.Lookup("health-port").DefValue {
			config.HealthCheckPort = *healthCheckPort
		}
		if flag.Lookup("event-cache-size").Value.String() != flag.Lookup("event-cache-size").DefValue {
			config.EventCacheSize = *eventCacheSize
		}
		if flag.Lookup("event-cache-window").Value.String() != flag.Lookup("event-cache-window").DefValue {
			config.EventCacheWindow = *eventCacheWindow
		}
		if flag.Lookup("enable-event-cache").Value.String() != flag.Lookup("enable-event-cache").DefValue {
			config.EnableEventCache = *enableEventCache
		}
		if flag.Lookup("initial-lookback-hours").Value.String() != flag.Lookup("initial-lookback-hours").DefValue {
			config.InitialLookbackHours = *initialLookback
		}
		if flag.Lookup("poll-overlap-minutes").Value.String() != flag.Lookup("poll-overlap-minutes").DefValue {
			config.PollOverlapMinutes = *pollOverlap
		}
		if flag.Lookup("max-events-per-poll").Value.String() != flag.Lookup("max-events-per-poll").DefValue {
			config.MaxEventsPerPoll = *maxEvents
		}
	}

	return config
}

func getJSONErrorPosition(data []byte, offset int64) (line, col int) {
	line = 1
	col = 1
	for i := int64(0); i < offset && i < int64(len(data)); i++ {
		if data[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

func loadConfigFromFile(config *Configuration, filename string) error {
	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", filename)
	}

	// Resolve relative paths
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return fmt.Errorf("failed to resolve config file path '%s': %w", filename, err)
	}

	// Check if file exists and is readable
	fileInfo, err := os.Stat(absPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", absPath)
	}
	if err != nil {
		return fmt.Errorf("cannot access config file '%s': %w", absPath, err)
	}

	// Check if it's a regular file
	if !fileInfo.Mode().IsRegular() {
		return fmt.Errorf("config file '%s' is not a regular file", absPath)
	}

	// Check file size (prevent loading huge files)
	if fileInfo.Size() > 1024*1024 { // 1MB limit
		return fmt.Errorf("config file '%s' is too large (%d bytes, max 1MB)", absPath, fileInfo.Size())
	}

	// Read file with better error context
	data, err := ioutil.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("failed to read config file '%s': %w", absPath, err)
	}

	// Validate JSON before unmarshaling
	if !json.Valid(data) {
		return fmt.Errorf("config file '%s' contains invalid JSON", absPath)
	}

	// Parse JSON with detailed error reporting
	var jsonConfig JSONConfig
	if err := json.Unmarshal(data, &jsonConfig); err != nil {
		// Try to provide line/column info for JSON errors
		if syntaxErr, ok := err.(*json.SyntaxError); ok {
			line, col := getJSONErrorPosition(data, syntaxErr.Offset)
			return fmt.Errorf("JSON syntax error in config file '%s' at line %d, column %d: %w", 
				absPath, line, col, err)
		}
		if typeErr, ok := err.(*json.UnmarshalTypeError); ok {
			line, col := getJSONErrorPosition(data, typeErr.Offset)
			return fmt.Errorf("JSON type error in config file '%s' at line %d, column %d, field '%s': expected %s but got %s", 
				absPath, line, col, typeErr.Field, typeErr.Type, typeErr.Value)
		}
		return fmt.Errorf("failed to parse config file '%s': %w", absPath, err)
	}

	log.Printf("📋 Successfully loaded configuration from: %s", absPath)

	// Apply configuration values from JSON file
	// Only override if the JSON value is non-empty/non-zero
	if jsonConfig.BitwardenAPI.APIBaseURL != "" {
		config.APIBaseURL = jsonConfig.BitwardenAPI.APIBaseURL
	}
	if jsonConfig.BitwardenAPI.IdentityURL != "" {
		config.IdentityURL = jsonConfig.BitwardenAPI.IdentityURL
	}
	if jsonConfig.BitwardenAPI.ClientID != "" {
		config.ClientID = jsonConfig.BitwardenAPI.ClientID
	}
	if jsonConfig.BitwardenAPI.ClientSecret != "" {
		config.ClientSecret = jsonConfig.BitwardenAPI.ClientSecret
	}
	if jsonConfig.Syslog.Server != "" {
		config.SyslogServer = jsonConfig.Syslog.Server
	}
	if jsonConfig.Syslog.Port != "" {
		config.SyslogPort = jsonConfig.Syslog.Port
	}
	if jsonConfig.Syslog.Protocol != "" {
		config.SyslogProtocol = jsonConfig.Syslog.Protocol
	}
	if jsonConfig.Polling.FetchInterval > 0 {
		config.FetchInterval = jsonConfig.Polling.FetchInterval
	}
	if jsonConfig.Polling.ConnectionTimeout > 0 {
		config.ConnTimeout = jsonConfig.Polling.ConnectionTimeout
	}
	if jsonConfig.Polling.MaxRetries > 0 {
		config.MaxRetries = jsonConfig.Polling.MaxRetries
	}
	if jsonConfig.Polling.RetryDelay > 0 {
		config.RetryDelay = jsonConfig.Polling.RetryDelay
	}
	if jsonConfig.Polling.InitialLookbackHours > 0 {
		config.InitialLookbackHours = jsonConfig.Polling.InitialLookbackHours
	}
	if jsonConfig.Polling.PollOverlapMinutes > 0 {
		config.PollOverlapMinutes = jsonConfig.Polling.PollOverlapMinutes
	}
	if jsonConfig.Polling.MaxEventsPerPoll > 0 {
		config.MaxEventsPerPoll = jsonConfig.Polling.MaxEventsPerPoll
	}
	if jsonConfig.Logging.LogLevel != "" {
		config.LogLevel = jsonConfig.Logging.LogLevel
	}
	if jsonConfig.Logging.LogFile != "" {
		config.LogFile = jsonConfig.Logging.LogFile
	}
	config.Verbose = jsonConfig.Logging.Verbose

	if jsonConfig.Files.MarkerFile != "" {
		config.MarkerFile = jsonConfig.Files.MarkerFile
	}
	if jsonConfig.Files.FieldMapFile != "" {
		config.FieldMapFile = jsonConfig.Files.FieldMapFile
	}
	if jsonConfig.Files.EventMapFile != "" {
		config.EventMapFile = jsonConfig.Files.EventMapFile
	}
	if jsonConfig.Monitoring.HealthCheckPort > 0 {
		config.HealthCheckPort = jsonConfig.Monitoring.HealthCheckPort
	}
	if jsonConfig.Monitoring.MaxMsgSize > 0 {
		config.MaxMsgSize = jsonConfig.Monitoring.MaxMsgSize
	}
	if jsonConfig.Monitoring.EventCacheSize > 0 {
		config.EventCacheSize = jsonConfig.Monitoring.EventCacheSize
	}
	if jsonConfig.Monitoring.EventCacheWindow > 0 {
		config.EventCacheWindow = jsonConfig.Monitoring.EventCacheWindow
	}
	config.EnableEventCache = jsonConfig.Monitoring.EnableEventCache

	return nil
}

// ADD better logging for configuration loading
func logConfigurationSource(config Configuration) {
	log.Printf("📋 Configuration Summary:")
	log.Printf("  📡 Syslog: %s:%s (%s)", config.SyslogServer, config.SyslogPort, config.SyslogProtocol)
	log.Printf("  ⏱️  Poll Interval: %ds", config.FetchInterval)
	log.Printf("  🔄 Max Retries: %d", config.MaxRetries)
	log.Printf("  🏥 Health Port: %d", config.HealthCheckPort)
	log.Printf("  📝 Log Level: %s", config.LogLevel)
	if config.LogFile != "" {
		log.Printf("  📁 Log File: %s", config.LogFile)
	}
	log.Printf("  🧠 Event Cache: %v (size: %d, window: %ds)", 
		config.EnableEventCache, config.EventCacheSize, config.EventCacheWindow)
}

// ADD configuration validation with warnings
func validateConfigWithWarnings(config Configuration) error {
	// Critical validation (these will cause errors)
	if err := validateConfig(config); err != nil {
		return err
	}

	// Warnings for suboptimal configurations
	warnings := []string{}

	if config.FetchInterval < 30 {
		warnings = append(warnings, 
			fmt.Sprintf("fetch interval of %ds is quite aggressive, consider >= 30s for production", 
			config.FetchInterval))
	}

	if config.MaxEventsPerPoll > 5000 {
		warnings = append(warnings, 
			fmt.Sprintf("max events per poll (%d) is very high, may cause memory issues", 
			config.MaxEventsPerPoll))
	}

	if config.EventCacheSize > 50000 {
		warnings = append(warnings, 
			fmt.Sprintf("event cache size (%d) is very large, may use significant memory", 
			config.EventCacheSize))
	}

	if config.SyslogProtocol == "udp" {
		warnings = append(warnings, 
			"UDP syslog protocol may lose messages under high load, consider TCP")
	}

	if config.InitialLookbackHours > 168 { // 1 week
		warnings = append(warnings, 
			fmt.Sprintf("initial lookback of %d hours is very long, may cause high initial load", 
			config.InitialLookbackHours))
	}

	// Log warnings
	for _, warning := range warnings {
		log.Printf("⚠️  Warning: %s", warning)
	}

	return nil
}

func createSampleConfigFile(filename string) error {
	sampleConfig := JSONConfig{
		BitwardenAPI: BitwardenAPIConfig{
			APIBaseURL:   "https://api.bitwarden.com",
			IdentityURL:  "https://identity.bitwarden.com",
			ClientID:     "your_client_id_from_bitwarden_portal",
			ClientSecret: "your_client_secret_from_bitwarden_portal",
		},
		Syslog: SyslogConfig{
			Server:   "your.syslog.server.com",
			Port:     "514",
			Protocol: "tcp",
		},
		Polling: PollingConfig{
			FetchInterval:         60,
			ConnectionTimeout:     30,
			MaxRetries:           3,
			RetryDelay:           5,
			MaxBackoffDelay:      300,
			InitialLookbackHours: 24,
			PollOverlapMinutes:   5,
			MaxEventsPerPoll:     1000,
		},
		Logging: LoggingConfig{
			LogLevel: "info",
			LogFile:  "/var/log/bitwarden-events.log",
			Verbose:  false,
		},
		Files: FilesConfig{
			MarkerFile:   "/var/lib/bitwarden/marker.txt",
			FieldMapFile: "/etc/bitwarden/bitwarden_field_map.json",
			EventMapFile: "/etc/bitwarden/bitwarden_event_map.json",
		},
		Monitoring: MonitoringConfig{
			HealthCheckPort:  8080,
			EnableMetrics:    true,
			MaxMsgSize:       8192,
			EventCacheSize:   10000,
			EventCacheWindow: 3600,
			EnableEventCache: true,
		},
	}

	data, err := json.MarshalIndent(sampleConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sample config: %w", err)
	}

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for config file: %w", err)
	}

	return ioutil.WriteFile(filename, data, 0644)
}

func validateConfigFile(filename string) error {
	log.Printf("🔍 Validating configuration file: %s", filename)
	
	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", filename)
	}
		
	// Create a temporary configuration to test loading
	tempConfig := Configuration{
		APIBaseURL:           "https://api.bitwarden.com",
		IdentityURL:          "https://identity.bitwarden.com",
		SyslogProtocol:       "tcp",
		SyslogServer:         "localhost",
		SyslogPort:           "514",
		LogLevel:             "info",
		FetchInterval:        60,
		ConnTimeout:          30,
		MaxMsgSize:           8192,
		MaxRetries:           3,
		RetryDelay:           5,
		HealthCheckPort:      8080,
		EventCacheSize:       10000,
		EventCacheWindow:     3600,
		EnableEventCache:     true,
		InitialLookbackHours: 24,
		PollOverlapMinutes:   5,
		MaxEventsPerPoll:     1000,
	}

	// Try to load the configuration
	if err := loadConfigFromFile(&tempConfig, filename); err != nil {
		return fmt.Errorf("failed to load config file: %w", err)
	}

	log.Printf("✅ Configuration file is valid: %s", filename)
	return nil
}

func validateConfig(config Configuration) error {
	var missing []string
	var errors []string

	// Required fields
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
		errors = append(errors, fmt.Sprintf("missing required configuration: %v", missing))
	}

	// Validation rules
	if config.FetchInterval < 10 {
		errors = append(errors, "fetch interval must be at least 10 seconds")
	}
	if config.ConnTimeout < 5 {
		errors = append(errors, "connection timeout must be at least 5 seconds")
	}
	if config.MaxRetries < 0 {
		errors = append(errors, "max retries must be 0 or greater")
	}
	if config.RetryDelay < 1 {
		errors = append(errors, "retry delay must be at least 1 second")
	}
	if config.MaxMsgSize < 512 {
		errors = append(errors, "max message size must be at least 512 bytes")
	}
	if config.HealthCheckPort < 0 || config.HealthCheckPort > 65535 {
		errors = append(errors, "health check port must be between 0 and 65535")
	}
	if config.EventCacheSize < 0 {
		errors = append(errors, "event cache size must be 0 or greater")
	}
	if config.EventCacheWindow < 0 {
		errors = append(errors, "event cache window must be 0 or greater")
	}
	if config.InitialLookbackHours < 1 {
		errors = append(errors, "initial lookback hours must be at least 1")
	}
	if config.PollOverlapMinutes < 0 {
		errors = append(errors, "poll overlap minutes must be 0 or greater")
	}
	if config.MaxEventsPerPoll < 1 {
		errors = append(errors, "max events per poll must be at least 1")
	}

	// Protocol validation
	if config.SyslogProtocol != "tcp" && config.SyslogProtocol != "udp" {
		errors = append(errors, "syslog protocol must be 'tcp' or 'udp'")
	}

	// Log level validation
	validLogLevels := []string{"debug", "info", "warn", "error"}
	isValidLogLevel := false
	for _, level := range validLogLevels {
		if config.LogLevel == level {
			isValidLogLevel = true
			break
		}
	}
	if !isValidLogLevel {
		errors = append(errors, fmt.Sprintf("log level must be one of: %v", validLogLevels))
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

func init() {
	memberListCache.membersByUserId = make(map[string]map[string]interface{})
	memberListCache.membersByOrgId = make(map[string]map[string]interface{})
	memberListCache.missedLookups = make(map[string]time.Time)
	memberListCache.ttl = 15 * time.Minute
}

// Diagnostic function to understand which users can be looked up
func diagnoseUserMembership(config Configuration) {
	log.Println("🔬 Diagnosing user membership and lookup capability...")
	
	// Get the organization member list
	url := config.APIBaseURL + "/public/members"
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("❌ Error creating request: %v", err)
		return
	}
	
	req.Header.Set("Authorization", "Bearer "+currentToken.AccessToken)
	req.Header.Set("User-Agent", "Bitwarden-Event-Forwarder/2.0")
	req.Header.Set("Accept", "application/json")
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("❌ Request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	
	if resp.StatusCode != 200 {
		log.Printf("❌ Members list failed with status %d: %s", resp.StatusCode, string(body))
		return
	}
	
	var membersResponse map[string]interface{}
	if err := json.Unmarshal(body, &membersResponse); err != nil {
		log.Printf("❌ Error parsing response: %v", err)
		return
	}
	
	dataInterface, exists := membersResponse["data"]
	if !exists {
		log.Printf("❌ No 'data' field in response")
		return
	}
	
	members, ok := dataInterface.([]interface{})
	if !ok {
		log.Printf("❌ 'data' field is not an array")
		return
	}
	
	log.Printf("📊 Organization has %d members", len(members))
	
	// Create a map of organization userIds for quick lookup
	orgUserIds := make(map[string]bool)
	
	log.Println("👥 Organization members:")
	for i, memberInterface := range members {
		if member, ok := memberInterface.(map[string]interface{}); ok {
			id := "unknown"
			userId := "unknown"
			name := "unknown"
			email := "unknown"
			
			if idVal, exists := member["id"]; exists {
				id = fmt.Sprintf("%v", idVal)
			}
			if userIdVal, exists := member["userId"]; exists {
				userId = fmt.Sprintf("%v", userIdVal)
				orgUserIds[userId] = true
			}
			if nameVal, exists := member["name"]; exists && nameVal != nil {
				name = fmt.Sprintf("%v", nameVal)
			}
			if emailVal, exists := member["email"]; exists {
				email = fmt.Sprintf("%v", emailVal)
			}
			
			log.Printf("   %d. OrgMemberID=%s, UserID=%s, Name=%s, Email=%s", 
				i+1, id, userId, name, email)
		}
	}
	
	// Now let's analyze some recent events to see what actingUserIds we're getting
	log.Println("🔍 Checking recent events for actingUserId patterns...")
	
	// This is a simplified version - you'd want to check your actual recent events
	log.Printf("📋 Summary:")
	log.Printf("   - Organization members who CAN be looked up: %d", len(orgUserIds))
	log.Printf("   - Use this list to check if event actingUserIds are organization members")
	log.Println("💡 Next step: Check if your event actingUserIds match any of the UserIDs above")
	
	return
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
	// Test field mapping file
	if _, err := os.Stat(config.FieldMapFile); os.IsNotExist(err) {
		defaultMapping := createDefaultFieldMapping()
		if err := saveFieldMapping(config.FieldMapFile, defaultMapping); err != nil {
			return fmt.Errorf("failed to create default field mapping: %w", err)
		}
		log.Printf("📋 Created default field mapping file: %s", config.FieldMapFile)
	}

	// Test event mapping file
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

func forwardEventsWithStats(events []BitwardenEvent, config Configuration, 
	fieldMapping FieldMapping, syslogWriter *SyslogWriter) (int, int, CacheStats, LookupStats, ChangeStats, error) {
	
	var forwarded, dropped int
	var cacheStats CacheStats
	var lookupStats LookupStats
	var changeStats ChangeStats
	
	for _, event := range events {
		eventKey := getEventDeduplicationKey(event)
		eventType := fmt.Sprintf("%d", event.Type)
		
		// Invalidate relevant caches for change events
		invalidateCache(eventType, fieldMapping)
		
		// Enrich the event with lookup data
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
		
		// Format and send the event
		cefMessage := formatEventAsCEF(enrichedEvent, config, fieldMapping)
		syslogMessage := formatSyslogMessage("bitwarden-forwarder", cefMessage)
		
		if len(syslogMessage) > config.MaxMsgSize {
			syslogMessage = syslogMessage[:config.MaxMsgSize]
			log.Printf("⚠️ Truncated message for event %s due to size limit", eventKey)
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
		
		// Mark as processed only after successful forwarding
		if eventCache != nil {
			eventCache.MarkProcessed(eventKey)
			if config.Verbose {
				log.Printf("✅ Forwarded enriched event: Key=%s, Type=%s (%s), User=%s (%s)", 
					eventKey, eventType, getStringValue(enrichedEvent, "eventTypeName"), 
					getStringValue(enrichedEvent, "memberId"), 
					getStringValue(enrichedEvent, "memberName"))
			}
		}
		
		forwarded++
	}
	
	return forwarded, dropped, cacheStats, lookupStats, changeStats, nil
}

func performMemberLookupFromList(lookupType, lookupId string, fieldMapping FieldMapping, config Configuration) (map[string]interface{}, bool, bool) {
	// Step 1: Ensure we have a fresh member list
	err := refreshMemberListCache(config)
	if err != nil {
		log.Printf("❌ Failed to refresh member list: %v", err)
		return nil, false, false
	}
	
	// Step 2: Determine which index to use based on lookup type
	var memberData map[string]interface{}
	var exists bool
	
	memberListCache.RLock()
	if lookupType == "actingUserId" {
		// actingUserId contains userId - look up by userId
		memberData, exists = memberListCache.membersByUserId[lookupId]
		if config.Verbose && exists {
			log.Printf("🔗 Found user %s in organization member list", lookupId)
		}
	} else if lookupType == "memberId" {
		// memberId contains organization member ID - look up by orgMemberId
		memberData, exists = memberListCache.membersByOrgId[lookupId]
		if config.Verbose && exists {
			log.Printf("🔗 Found org member %s in member list", lookupId)
		}
	}
	memberListCache.RUnlock()
	
	if !exists {
		// Check if we've recently missed this lookup
		memberListCache.RLock()
		lastMiss, recentMiss := memberListCache.missedLookups[lookupId]
		memberListCache.RUnlock()
		
		// If we haven't tried recently, force a cache refresh and retry ONCE
		if !recentMiss || time.Since(lastMiss) > 2*time.Minute {
			if config.Verbose {
				log.Printf("🔄 %s ID %s not found, forcing cache refresh and retrying", lookupType, lookupId)
			}
			
			// Force cache refresh
			memberListCache.Lock()
			memberListCache.lastUpdate = time.Time{} // Force refresh
			memberListCache.missedLookups[lookupId] = time.Now()
			memberListCache.Unlock()
			
			// Retry the refresh
			err := refreshMemberListCache(config)
			if err != nil {
				log.Printf("❌ Failed to force-refresh member list: %v", err)
				return nil, false, false
			}
			
			// Try lookup again with correct index
			memberListCache.RLock()
			if lookupType == "actingUserId" {
				memberData, exists = memberListCache.membersByUserId[lookupId]
			} else if lookupType == "memberId" {
				memberData, exists = memberListCache.membersByOrgId[lookupId]
			}
			memberListCache.RUnlock()
		}
		
		if !exists {
			if config.Verbose {
				log.Printf("⚠️ %s ID %s not found in member list (even after refresh)", lookupType, lookupId)
			}
			return nil, false, false
		}
	}
	
	// Step 3: Map the member data according to field mapping config
	lookupConfig, exists := fieldMapping.Lookups[lookupType]
	if !exists {
		return nil, false, false
	}
	
	mappedData := mapResponseData(memberData, lookupConfig.ResponseMapping)
	
	// Cache the result using the original lookupId as key
	lookupCache.Lock()
	if lookupCache.data[lookupType] == nil {
		lookupCache.data[lookupType] = make(map[string]interface{})
	}
	lookupCache.data[lookupType][lookupId] = mappedData
	lookupCache.Unlock()
	
	// Clear any missed lookup tracking for this ID since it succeeded
	memberListCache.Lock()
	delete(memberListCache.missedLookups, lookupId)
	memberListCache.Unlock()
	
	if config.Verbose {
		log.Printf("✅ Successfully looked up %s %s: %s", 
			lookupType, lookupId, getStringValue(mappedData, "userName"))
	}
	
	return mappedData, false, true
}

func refreshMemberListCache(config Configuration) error {
	memberListCache.Lock()
	defer memberListCache.Unlock()
	
	// Check if cache is still valid
	if time.Since(memberListCache.lastUpdate) < memberListCache.ttl {
		return nil // Cache is still fresh
	}
	
	// Fetch fresh member list
	url := config.APIBaseURL + "/public/members"
	
	if config.Verbose {
		log.Printf("🔄 Refreshing member list cache from: %s", url)
	}
	
	data, success := makeBitwardenAPIRequest(url, config)
	if !success {
		return fmt.Errorf("failed to fetch member list")
	}
	
	// Parse the response
	dataInterface, exists := data["data"]
	if !exists {
		return fmt.Errorf("no 'data' field in member list response")
	}
	
	members, ok := dataInterface.([]interface{})
	if !ok {
		return fmt.Errorf("'data' field is not an array")
	}
	
	// Clear and rebuild both caches
	oldUserCount := len(memberListCache.membersByUserId)
	oldOrgCount := len(memberListCache.membersByOrgId)
	memberListCache.membersByUserId = make(map[string]map[string]interface{})
	memberListCache.membersByOrgId = make(map[string]map[string]interface{})
	
	for _, memberInterface := range members {
		member, ok := memberInterface.(map[string]interface{})
		if !ok {
			continue
		}
		
		// Index by BOTH userId AND organization member ID
		if userIdInterface, exists := member["userId"]; exists {
			userId := fmt.Sprintf("%v", userIdInterface)
			memberListCache.membersByUserId[userId] = member
		}
		
		if idInterface, exists := member["id"]; exists {
			orgMemberId := fmt.Sprintf("%v", idInterface)
			memberListCache.membersByOrgId[orgMemberId] = member
		}
	}
	
	memberListCache.lastUpdate = time.Now()
	
	newUserCount := len(memberListCache.membersByUserId)
	newOrgCount := len(memberListCache.membersByOrgId)
	
	if oldUserCount != newUserCount || oldOrgCount != newOrgCount {
		log.Printf("📊 Member cache updated - by userId: %d -> %d, by orgId: %d -> %d", 
			oldUserCount, newUserCount, oldOrgCount, newOrgCount)
	}
	
	log.Printf("✅ Cached %d members by userId and %d by orgId for lookup", newUserCount, newOrgCount)
	return nil
}

// Perform lookup with caching
func performLookup(lookupType, id string, fieldMapping FieldMapping, config Configuration) (map[string]interface{}, bool, bool) {
	// Check cache first for final result
	lookupCache.RLock()
	if cachedData, exists := lookupCache.data[lookupType]; exists {
		if data, found := cachedData[id]; found {
			lookupCache.RUnlock()
			return data.(map[string]interface{}), true, true
		}
	}
	lookupCache.RUnlock()
	
	// For member/user lookups, use the member list approach
	if lookupType == "actingUserId" || lookupType == "memberId" {
		return performMemberLookupFromList(lookupType, id, fieldMapping, config)
	}
	
	// For other lookups (groups, collections, policies), use direct lookup
	lookupConfig, exists := fieldMapping.Lookups[lookupType]
	if !exists {
		return nil, false, false
	}
	
	endpoint := strings.Replace(lookupConfig.Endpoint, "{id}", id, -1)
	url := config.APIBaseURL + endpoint
	
	if config.Verbose {
		log.Printf("🔍 Direct lookup %s: %s", lookupType, url)
	}
	
	data, success := makeBitwardenAPIRequest(url, config)
	if success {
		mappedData := mapResponseData(data, lookupConfig.ResponseMapping)
		
		// Cache the result
		lookupCache.Lock()
		if lookupCache.data[lookupType] == nil {
			lookupCache.data[lookupType] = make(map[string]interface{})
		}
		lookupCache.data[lookupType][id] = mappedData
		lookupCache.Unlock()
		
		return mappedData, false, true
	}
	
	return nil, false, false
}

// Make authenticated API request to Bitwarden
func makeBitwardenAPIRequest(url string, config Configuration) (map[string]interface{}, bool) {
	// Ensure we have a valid token
	if currentToken == nil || time.Now().After(currentToken.ExpiresAt.Add(-5*time.Minute)) {
		if err := authenticateWithBitwarden(config); err != nil {
			log.Printf("❌ Token refresh failed during lookup: %v", err)
			return nil, false
		}
	}
	
	// Create the request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("❌ Error creating lookup request: %v", err)
		return nil, false
	}
	
	req.Header.Set("Authorization", "Bearer "+currentToken.AccessToken)
	req.Header.Set("User-Agent", "Bitwarden-Event-Forwarder/2.0")
	req.Header.Set("Accept", "application/json")
	
	// Make the request with timeout
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("❌ Lookup request failed: %v", err)
		return nil, false
	}
	defer resp.Body.Close()
	
	// Handle different response codes
	if resp.StatusCode == 404 {
		// Resource not found - this is normal for deleted/removed items
		log.Printf("ℹ️ Resource not found (404) for URL: %s", url)
		return map[string]interface{}{"error": "not_found"}, true
	}
	
	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("❌ Lookup API returned status %d: %s", resp.StatusCode, string(body))
		return nil, false
	}
	
	// Parse the JSON response
	var responseData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		log.Printf("❌ Error parsing lookup response: %v", err)
		return nil, false
	}
	
	return responseData, true
}

// Map API response data according to field mapping configuration
func mapResponseData(apiResponse map[string]interface{}, responseMapping map[string]string) map[string]interface{} {
	mapped := make(map[string]interface{})
	
	// Apply explicit mappings from configuration
	for apiField, outputField := range responseMapping {
		if value, exists := apiResponse[apiField]; exists {
			mapped[outputField] = value
		}
	}
	
	// Add some commonly useful fields directly if they exist
	commonFields := []string{"id", "name", "email", "status", "type", "object"}
	for _, field := range commonFields {
		if value, exists := apiResponse[field]; exists {
			// Only add if not already mapped
			if _, alreadyMapped := mapped[field]; !alreadyMapped {
				mapped[field] = value
			}
		}
	}
	
	return mapped
}

// Cache invalidation function to handle cache cleanup when entities change
func invalidateCache(eventType string, fieldMapping FieldMapping) {
	if rules, exists := fieldMapping.CacheInvalidationRules[eventType]; exists {
		lookupCache.Lock()
		
		// Track if we need to invalidate member list cache
		needMemberListRefresh := false
		
		for _, cacheType := range rules {
			if _, exists := lookupCache.data[cacheType]; exists {
				// Clear entire cache for this type
				delete(lookupCache.data, cacheType)
				log.Printf("🧹 Invalidated cache for %s due to event type %s", cacheType, eventType)
			}
			
			// Only invalidate member list cache for organization member changes
			// NOT for actingUserId (which could be external users)
			if cacheType == "memberId" {
				needMemberListRefresh = true
			}
		}
		lookupCache.Unlock()
		
		// Invalidate member list cache if needed
		if needMemberListRefresh {
			memberListCache.Lock()
			memberListCache.lastUpdate = time.Time{} // Force refresh on next lookup
			// Also clear missed lookups since we're refreshing
			memberListCache.missedLookups = make(map[string]time.Time)
			memberListCache.Unlock()
			log.Printf("🧹 Invalidated member list cache due to event type %s", eventType)
		}
	}
}

// Helper function to safely get string values from enriched event data
func getStringValue(data map[string]interface{}, key string) string {
	if value, exists := data[key]; exists && value != nil {
		return fmt.Sprintf("%v", value)
	}
	return ""
}

func enrichEvent(event BitwardenEvent, fieldMapping FieldMapping, config Configuration) (map[string]interface{}, bool, bool) {
	// CRITICAL: Preserve the original event type and structure FIRST
	enriched := map[string]interface{}{
		"date":            event.Date.Format(time.RFC3339),
		"event_type":      event.Type,    // Preserve original event type as event_type
		"type":            event.Type,    // Also keep as type for mapping
		"device":          event.Device,
		"object":          event.Object,
		"eventKey":        getEventDeduplicationKey(event),
	}
	
	// Copy all original IDs as-is for reference (late in mapping order)
	if event.ActingUserID != nil {
		enriched["actingUserId"] = *event.ActingUserID
		enriched["actingUserIdOriginal"] = *event.ActingUserID  // Preserve original GUID
	}
	if event.MemberID != nil {
		enriched["memberId"] = *event.MemberID
		enriched["memberIdOriginal"] = *event.MemberID  // Preserve original GUID
	}
	if event.GroupID != nil {
		enriched["groupId"] = *event.GroupID
		enriched["groupIdOriginal"] = *event.GroupID  // Preserve original GUID
	}
	if event.CollectionID != nil {
		enriched["collectionId"] = *event.CollectionID
		enriched["collectionIdOriginal"] = *event.CollectionID  // Preserve original GUID
	}
	if event.PolicyID != nil {
		enriched["policyId"] = *event.PolicyID
		enriched["policyIdOriginal"] = *event.PolicyID  // Preserve original GUID
	}
	if event.ItemID != nil {
		enriched["itemId"] = *event.ItemID
		enriched["itemIdOriginal"] = *event.ItemID  // Preserve original GUID
	}
	if event.InstallationID != nil {
		enriched["installationId"] = *event.InstallationID
		enriched["installationIdOriginal"] = *event.InstallationID  // Preserve original GUID
	}
	if event.IPAddress != nil {
		enriched["ipAddress"] = *event.IPAddress
	}
	
	// Add human-readable event type name
	if eventName, exists := eventTypeMap[fmt.Sprintf("%d", event.Type)]; exists {
		enriched["eventTypeName"] = eventName
	} else {
		enriched["eventTypeName"] = fmt.Sprintf("Unknown Event (%d)", event.Type)
	}
	
	// Add device type name
	enriched["deviceTypeName"] = getDeviceTypeName(event.Device)
	
	// NOW do lookups - but be careful about field name collisions
	cacheHit := true
	lookupSuccess := true
	
	// Lookup acting user
	if event.ActingUserID != nil {
		userInfo, hit, success := performLookup("actingUserId", *event.ActingUserID, fieldMapping, config)
		if success {
			// Add user info with SPECIFIC field names to avoid collision
			enriched["userName"] = getStringValue(userInfo, "userName")
			enriched["userEmail"] = getStringValue(userInfo, "userEmail")
			enriched["userStatus"] = getStringValue(userInfo, "userStatus")
			enriched["user2FA"] = getStringValue(userInfo, "user2FA")
			// Store user type with prefixed name to avoid collision with event type
			enriched["userType"] = getStringValue(userInfo, "userType")
		}
		if !hit { cacheHit = false }
		if !success { lookupSuccess = false }
	}
	
	// Lookup member (if different from acting user)
	if event.MemberID != nil {
		memberInfo, hit, success := performLookup("memberId", *event.MemberID, fieldMapping, config)
		if success {
			// Add member info with SPECIFIC field names
			enriched["memberName"] = getStringValue(memberInfo, "memberName")
			enriched["memberEmail"] = getStringValue(memberInfo, "memberEmail")
			enriched["memberStatus"] = getStringValue(memberInfo, "memberStatus")
			enriched["member2FA"] = getStringValue(memberInfo, "member2FA")
			// Store member type with prefixed name
			enriched["memberType"] = getStringValue(memberInfo, "memberType")
		}
		if !hit { cacheHit = false }
		if !success { lookupSuccess = false }
	}
	
	// Lookup group
	if event.GroupID != nil {
		groupInfo, hit, success := performLookup("groupId", *event.GroupID, fieldMapping, config)
		if success {
			enriched["groupName"] = getStringValue(groupInfo, "groupName")
			enriched["groupAccessAll"] = getStringValue(groupInfo, "groupAccessAll")
		}
		if !hit { cacheHit = false }
		if !success { lookupSuccess = false }
	}
	
	// Lookup collection
	if event.CollectionID != nil {
		collectionInfo, hit, success := performLookup("collectionId", *event.CollectionID, fieldMapping, config)
		if success {
			enriched["collectionName"] = getStringValue(collectionInfo, "collectionName")
		}
		if !hit { cacheHit = false }
		if !success { lookupSuccess = false }
	}
	
	// Lookup policy
	if event.PolicyID != nil {
		policyInfo, hit, success := performLookup("policyId", *event.PolicyID, fieldMapping, config)
		if success {
			enriched["policyName"] = getStringValue(policyInfo, "policyName")
			// Store policy type with prefixed name to avoid collision
			enriched["policyType"] = getStringValue(policyInfo, "policyType")
			enriched["policyEnabled"] = getStringValue(policyInfo, "policyEnabled")
		}
		if !hit { cacheHit = false }
		if !success { lookupSuccess = false }
	}
	
	// DOUBLE CHECK: Make sure original event type is preserved
	enriched["event_type"] = event.Type
	enriched["type"] = event.Type
	
	if config.Verbose {
		log.Printf("🔍 Event preserved: original_type=%d, final_type=%v", 
			event.Type, enriched["type"])
	}
	
	return enriched, cacheHit, lookupSuccess
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
	if enrichedName, exists := event["eventTypeName"]; exists {
        eventName = fmt.Sprintf("%v", enrichedName)
    }
	
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
			"rt", "cs1", "cs2", "suser", "email", "userName", "userEmail", "userStatus", 
			"memberName", "memberEmail", "groupName", "collectionName", "policyName",
			"status", "2fa", "host_ip", "device", "deviceTypeName", "groupId", "collectionId", "policyId", 
			"memberId", "objectname", "eventTypeName", "userIdOriginal", "memberIdOriginal",
			"groupIdOriginal", "collectionIdOriginal", "policyIdOriginal", "community", "roles", 
			"caseName", "hasDataChanges", "changeType", "changeCount", "changedFields", "oldValues", "newValues",
		},
		FieldMappings: map[string]string{
			"date":               "rt",
			"type":               "cs1",
			"eventKey":           "cs2",
			"actingUserId":       "suser",        // Primary user field - the GUID that shows up
			"userName":           "userName",     // Human-readable name from lookup
			"userEmail":          "email",       // Human-readable email from lookup
			"userStatus":         "status",      // User status from lookup
			"user2FA":            "2fa",         // 2FA status from lookup
			"memberId":           "memberId",    // Secondary field (often empty)
			"memberName":         "memberName",  // Member name if different from acting user
			"memberEmail":        "memberEmail", // Member email if different from acting user
			"ipAddress":          "host_ip",
			"device":             "device",
			"deviceTypeName":     "deviceTypeName",
			"groupId":            "groupId",
			"groupName":          "groupName",
			"collectionId":       "collectionId",
			"collectionName":     "collectionName",
			"policyId":           "policyId",
			"policyName":         "policyName",
			"object":             "objectname",
			"eventTypeName":      "eventTypeName",
		},
		Lookups: map[string]LookupConfig{
			"actingUserId": {  // Changed from "memberId" to "actingUserId"
				Endpoint: "/public/members/{id}",
				ResponseMapping: map[string]string{
					"name":                     "userName",     // Maps to primary user name
					"email":                    "userEmail",    // Maps to primary user email
					"status":                   "userStatus",   // Maps to primary user status
					"twoFactorEnabled":         "user2FA",      // Maps to primary user 2FA
					"type":                     "userType",
					"accessAll":                "userAccessAll",
					"externalId":               "userExternalId",
					"resetPasswordEnrolled":    "userResetPasswordEnrolled",
				},
			},
			"memberId": {  // Keep this for cases where memberId is populated separately
				Endpoint: "/public/members/{id}",
				ResponseMapping: map[string]string{
					"name":                     "memberName",
					"email":                    "memberEmail",
					"status":                   "memberStatus",
					"twoFactorEnabled":         "member2FA",
					"type":                     "memberType",
					"accessAll":                "memberAccessAll",
					"externalId":               "memberExternalId",
					"resetPasswordEnrolled":    "memberResetPasswordEnrolled",
				},
			},
			"groupId": {
				Endpoint: "/public/groups/{id}",
				ResponseMapping: map[string]string{
					"name":         "groupName",
					"accessAll":    "groupAccessAll",
					"externalId":   "groupExternalId",
				},
			},
			"collectionId": {
				Endpoint: "/public/collections/{id}",
				ResponseMapping: map[string]string{
					"name":         "collectionName",
					"externalId":   "collectionExternalId",
				},
			},
			"policyId": {
				Endpoint: "/public/policies/{id}",
				ResponseMapping: map[string]string{
					"type":         "policyType",
					"data":         "policyData",
					"enabled":      "policyEnabled",
				},
			},
		},
		CacheInvalidationRules: map[string][]string{
			"1700": {"policyId"},
			"1500": {"actingUserId", "memberId"},  // Added actingUserId
			"1502": {"actingUserId", "memberId"},  // Added actingUserId
			"1503": {"actingUserId", "memberId"},  // Added actingUserId
			"1504": {"actingUserId", "memberId"},  // Added actingUserId
			"1505": {"actingUserId", "memberId"},  // Added actingUserId
			"1400": {"groupId"},
			"1401": {"groupId"},
			"1402": {"groupId"},
			"1300": {"collectionId"},
			"1301": {"collectionId"},
			"1302": {"collectionId"},
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
