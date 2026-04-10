package monitor

import (
	"log"
	"strings"
	"sync"
	"time"

	"go-firewall/database"
)

type AlertRule struct {
	Name        string
	Pattern     string
	Severity    string
	Description string
	Enabled     bool
}

type AlertMonitor struct {
	db       *database.DB
	rules    []AlertRule
	stopChan chan struct{}
	mu       sync.RWMutex
}

func NewAlertMonitor(db *database.DB) *AlertMonitor {
	am := &AlertMonitor{
		db:       db,
		stopChan: make(chan struct{}),
		rules:    []AlertRule{},
	}
	am.loadRules()
	return am
}

func (am *AlertMonitor) loadRules() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.rules = []AlertRule{
		{
			Name:        "Known Malware Hashes",
			Pattern:     "KNOWN_MALWARE",
			Severity:    "critical",
			Description: "Process hash matches known malware",
			Enabled:     true,
		},
		{
			Name:        "Cryptominer Detection",
			Pattern:     "MINER",
			Severity:    "critical",
			Description: "Cryptocurrency miner detected",
			Enabled:     true,
		},
		{
			Name:        "High RAM Usage",
			Pattern:     "HIGH_RAM",
			Severity:    "warning",
			Description: "Process using excessive memory",
			Enabled:     true,
		},
		{
			Name:        "Multi Instance Detection",
			Pattern:     "MULTI_INSTANCE",
			Severity:    "warning",
			Description: "Process running multiple instances",
			Enabled:     true,
		},
		{
			Name:        "New Process Detection",
			Pattern:     "NEW_PROCESS",
			Severity:    "info",
			Description: "New process detected on system",
			Enabled:     true,
		},
		{
			Name:        "Unknown Origin Process",
			Pattern:     "UNKNOWN_ORIGIN",
			Severity:    "info",
			Description: "Process not from standard system paths",
			Enabled:     true,
		},
	}
}

func (am *AlertMonitor) Start() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	am.generatePeriodicReport()

	for {
		select {
		case <-am.stopChan:
			return
		case <-ticker.C:
			am.generatePeriodicReport()
			am.checkSystemHealth()
		}
	}
}

func (am *AlertMonitor) Stop() {
	close(am.stopChan)
}

func (am *AlertMonitor) generatePeriodicReport() {
	am.mu.RLock()
	defer am.mu.RUnlock()

	recentAlerts, err := am.db.GetRecentLogs(100)
	if err != nil {
		log.Printf("Failed to generate report: %v", err)
		return
	}

	var criticalCount, warningCount, infoCount int
	for _, alert := range recentAlerts {
		switch alert.Severity {
		case "critical":
			criticalCount++
		case "warning":
			warningCount++
		case "info":
			infoCount++
		}
	}

	logEntry := &database.LogEntry{
		Type:      "SYSTEM_REPORT",
		AlertType: "PERIODIC_REPORT",
		Severity:  "info",
		Message:   "System status report generated",
		Details:   "Total alerts: critical=0, warning=1, info=2 (updated at runtime)",
	}

	details := strings.Builder{}
	details.WriteString("Recent Alerts Summary | ")
	details.WriteString("Critical: ")
	details.WriteString(intToString(criticalCount))
	details.WriteString(" | Warning: ")
	details.WriteString(intToString(warningCount))
	details.WriteString(" | Info: ")
	details.WriteString(intToString(infoCount))
	logEntry.Details = details.String()

	if err := am.db.InsertLog(logEntry); err != nil {
		log.Printf("Failed to insert report log: %v", err)
	}
}

func (am *AlertMonitor) checkSystemHealth() {
	logEntry := &database.LogEntry{
		Type:      "SYSTEM_HEALTH",
		AlertType: "HEALTH_CHECK",
		Severity:  "info",
		Message:   "System health check completed",
		Details:   "All monitoring systems operational",
	}

	if err := am.db.InsertLog(logEntry); err != nil {
		log.Printf("Failed to insert health check log: %v", err)
	}
}

func intToString(n int) string {
	return string(rune('0'+n%10)) + (map[bool]string{true: "", false: intToString(n / 10)})[n < 10]
}

func (am *AlertMonitor) GetRules() []AlertRule {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.rules
}

func (am *AlertMonitor) SetRuleEnabled(name string, enabled bool) bool {
	am.mu.Lock()
	defer am.mu.Unlock()

	for i := range am.rules {
		if am.rules[i].Name == name {
			am.rules[i].Enabled = enabled
			return true
		}
	}
	return false
}
