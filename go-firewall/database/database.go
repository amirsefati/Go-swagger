package database

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type LogEntry struct {
	ID           int64     `json:"id"`
	Type         string    `json:"type"`
	Timestamp    time.Time `json:"timestamp"`
	AlertType    string    `json:"alert_type"`
	Severity     string    `json:"severity"`
	PID          int32     `json:"pid,omitempty"`
	ProcessName  string    `json:"process_name,omitempty"`
	Message      string    `json:"message"`
	Details      string    `json:"details,omitempty"`
	SourceIP     string    `json:"source_ip,omitempty"`
	DestIP       string    `json:"dest_ip,omitempty"`
	DestPort     int       `json:"dest_port,omitempty"`
	FileHash     string    `json:"file_hash,omitempty"`
	IsNew        bool      `json:"is_new,omitempty"`
	IsSuspicious bool      `json:"is_suspicious,omitempty"`
}

type DB struct {
	*sql.DB
}

func InitDatabase(dbPath string) (*DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	wrapper := &DB{db}
	if err := wrapper.createTables(); err != nil {
		return nil, err
	}

	log.Printf("Database initialized: %s", dbPath)
	return wrapper, nil
}

func (db *DB) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			alert_type TEXT,
			severity TEXT,
			pid INTEGER,
			process_name TEXT,
			message TEXT,
			details TEXT,
			source_ip TEXT,
			dest_ip TEXT,
			dest_port INTEGER,
			file_hash TEXT,
			is_new INTEGER DEFAULT 0,
			is_suspicious INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS process_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pid INTEGER NOT NULL,
			process_name TEXT NOT NULL,
			exe_path TEXT,
			command_line TEXT,
			ram_mb REAL,
			cpu_percent REAL,
			start_time DATETIME,
			file_hash TEXT,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_suspicious INTEGER DEFAULT 0,
			run_count INTEGER DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS whitelist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			value TEXT NOT NULL,
			reason TEXT,
			added_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_logs_type ON logs(type)`,
		`CREATE INDEX IF NOT EXISTS idx_process_history_pid ON process_history(pid)`,
		`CREATE INDEX IF NOT EXISTS idx_process_history_name ON process_history(process_name)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	return nil
}

func (db *DB) InsertLog(entry *LogEntry) error {
	query := `INSERT INTO logs (type, alert_type, severity, pid, process_name, message, details, source_ip, dest_ip, dest_port, file_hash, is_new, is_suspicious)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := db.Exec(query,
		entry.Type,
		entry.AlertType,
		entry.Severity,
		entry.PID,
		entry.ProcessName,
		entry.Message,
		entry.Details,
		entry.SourceIP,
		entry.DestIP,
		entry.DestPort,
		entry.FileHash,
		entry.IsNew,
		entry.IsSuspicious,
	)
	if err != nil {
		return err
	}

	id, _ := result.LastInsertId()
	entry.ID = id
	entry.Timestamp = time.Now()

	return nil
}

func (db *DB) GetRecentLogs(limit int) ([]LogEntry, error) {
	query := `SELECT id, type, timestamp, alert_type, severity, pid, process_name, message, details, source_ip, dest_ip, dest_port, file_hash, is_new, is_suspicious
		FROM logs ORDER BY timestamp DESC LIMIT ?`

	rows, err := db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		var entry LogEntry
		err := rows.Scan(
			&entry.ID,
			&entry.Type,
			&entry.Timestamp,
			&entry.AlertType,
			&entry.Severity,
			&entry.PID,
			&entry.ProcessName,
			&entry.Message,
			&entry.Details,
			&entry.SourceIP,
			&entry.DestIP,
			&entry.DestPort,
			&entry.FileHash,
			&entry.IsNew,
			&entry.IsSuspicious,
		)
		if err != nil {
			continue
		}
		logs = append(logs, entry)
	}

	return logs, nil
}

func (db *DB) GetLogsByType(logType string, limit int) ([]LogEntry, error) {
	query := `SELECT id, type, timestamp, alert_type, severity, pid, process_name, message, details, source_ip, dest_ip, dest_port, file_hash, is_new, is_suspicious
		FROM logs WHERE type = ? ORDER BY timestamp DESC LIMIT ?`

	rows, err := db.Query(query, logType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		var entry LogEntry
		err := rows.Scan(
			&entry.ID,
			&entry.Type,
			&entry.Timestamp,
			&entry.AlertType,
			&entry.Severity,
			&entry.PID,
			&entry.ProcessName,
			&entry.Message,
			&entry.Details,
			&entry.SourceIP,
			&entry.DestIP,
			&entry.DestPort,
			&entry.FileHash,
			&entry.IsNew,
			&entry.IsSuspicious,
		)
		if err != nil {
			continue
		}
		logs = append(logs, entry)
	}

	return logs, nil
}

func (db *DB) GetLogsBySeverity(severity string, limit int) ([]LogEntry, error) {
	query := `SELECT id, type, timestamp, alert_type, severity, pid, process_name, message, details, source_ip, dest_ip, dest_port, file_hash, is_new, is_suspicious
		FROM logs WHERE severity = ? ORDER BY timestamp DESC LIMIT ?`

	rows, err := db.Query(query, severity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		var entry LogEntry
		err := rows.Scan(
			&entry.ID,
			&entry.Type,
			&entry.Timestamp,
			&entry.AlertType,
			&entry.Severity,
			&entry.PID,
			&entry.ProcessName,
			&entry.Message,
			&entry.Details,
			&entry.SourceIP,
			&entry.DestIP,
			&entry.DestPort,
			&entry.FileHash,
			&entry.IsNew,
			&entry.IsSuspicious,
		)
		if err != nil {
			continue
		}
		logs = append(logs, entry)
	}

	return logs, nil
}

func (db *DB) GetSuspiciousLogs(limit int) ([]LogEntry, error) {
	query := `SELECT id, type, timestamp, alert_type, severity, pid, process_name, message, details, source_ip, dest_ip, dest_port, file_hash, is_new, is_suspicious
		FROM logs WHERE is_suspicious = 1 ORDER BY timestamp DESC LIMIT ?`

	rows, err := db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		var entry LogEntry
		err := rows.Scan(
			&entry.ID,
			&entry.Type,
			&entry.Timestamp,
			&entry.AlertType,
			&entry.Severity,
			&entry.PID,
			&entry.ProcessName,
			&entry.Message,
			&entry.Details,
			&entry.SourceIP,
			&entry.DestIP,
			&entry.DestPort,
			&entry.FileHash,
			&entry.IsNew,
			&entry.IsSuspicious,
		)
		if err != nil {
			continue
		}
		logs = append(logs, entry)
	}

	return logs, nil
}

func (db *DB) GetLogsByTimeRange(start, end time.Time) ([]LogEntry, error) {
	query := `SELECT id, type, timestamp, alert_type, severity, pid, process_name, message, details, source_ip, dest_ip, dest_port, file_hash, is_new, is_suspicious
		FROM logs WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC`

	rows, err := db.Query(query, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		var entry LogEntry
		err := rows.Scan(
			&entry.ID,
			&entry.Type,
			&entry.Timestamp,
			&entry.AlertType,
			&entry.Severity,
			&entry.PID,
			&entry.ProcessName,
			&entry.Message,
			&entry.Details,
			&entry.SourceIP,
			&entry.DestIP,
			&entry.DestPort,
			&entry.FileHash,
			&entry.IsNew,
			&entry.IsSuspicious,
		)
		if err != nil {
			continue
		}
		logs = append(logs, entry)
	}

	return logs, nil
}

func (db *DB) InsertProcessHistory(pid int32, name, exePath, cmdLine string, ramMB, cpuPercent float64, fileHash string, isSuspicious bool) error {
	query := `INSERT INTO process_history (pid, process_name, exe_path, command_line, ram_mb, cpu_percent, file_hash, is_suspicious)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(query, pid, name, exePath, cmdLine, ramMB, cpuPercent, fileHash, isSuspicious)
	return err
}

func (db *DB) GetProcessHistory(limit int) ([]map[string]interface{}, error) {
	query := `SELECT id, pid, process_name, exe_path, command_line, ram_mb, cpu_percent, start_time, last_seen, is_suspicious, run_count
		FROM process_history ORDER BY last_seen DESC LIMIT ?`

	rows, err := db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []map[string]interface{}
	for rows.Next() {
		row := make(map[string]interface{})
		var id int64
		var pid int
		var name, exePath, cmdLine string
		var ramMB, cpuPercent float64
		var startTime, lastSeen time.Time
		var isSuspicious bool
		var runCount int

		rows.Scan(&id, &pid, &name, &exePath, &cmdLine, &ramMB, &cpuPercent, &startTime, &lastSeen, &isSuspicious, &runCount)

		row["id"] = id
		row["pid"] = pid
		row["process_name"] = name
		row["exe_path"] = exePath
		row["command_line"] = cmdLine
		row["ram_mb"] = ramMB
		row["cpu_percent"] = cpuPercent
		row["start_time"] = startTime
		row["last_seen"] = lastSeen
		row["is_suspicious"] = isSuspicious
		row["run_count"] = runCount

		history = append(history, row)
	}

	return history, nil
}

func (db *DB) AddToWhitelist(wtype, value, reason string) error {
	query := `INSERT INTO whitelist (type, value, reason) VALUES (?, ?, ?)`
	_, err := db.Exec(query, wtype, value, reason)
	return err
}

func (db *DB) GetWhitelist() ([]map[string]interface{}, error) {
	query := `SELECT id, type, value, reason, added_at FROM whitelist ORDER BY added_at DESC`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var whitelist []map[string]interface{}
	for rows.Next() {
		row := make(map[string]interface{})
		var id int64
		var wtype, value, reason string
		var addedAt time.Time

		rows.Scan(&id, &wtype, &value, &reason, &addedAt)

		row["id"] = id
		row["type"] = wtype
		row["value"] = value
		row["reason"] = reason
		row["added_at"] = addedAt

		whitelist = append(whitelist, row)
	}

	return whitelist, nil
}

func (db *DB) GetStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	queries := map[string]string{
		"total_logs":        "SELECT COUNT(*) FROM logs",
		"critical_count":    "SELECT COUNT(*) FROM logs WHERE severity = 'critical'",
		"warning_count":     "SELECT COUNT(*) FROM logs WHERE severity = 'warning'",
		"info_count":        "SELECT COUNT(*) FROM logs WHERE severity = 'info'",
		"process_count":     "SELECT COUNT(DISTINCT process_name) FROM process_history",
		"malicious_count":   "SELECT COUNT(*) FROM logs WHERE alert_type = 'KNOWN_THREAT'",
		"new_process_count": "SELECT COUNT(*) FROM logs WHERE alert_type = 'NEW_PROCESS'",
	}

	for key, query := range queries {
		var count int
		db.QueryRow(query).Scan(&count)
		stats[key] = count
	}

	var avgRAM float64
	db.QueryRow("SELECT AVG(ram_mb) FROM process_history").Scan(&avgRAM)
	stats["avg_ram"] = avgRAM

	var maxRAM float64
	db.QueryRow("SELECT MAX(ram_mb) FROM process_history").Scan(&maxRAM)
	stats["max_ram"] = maxRAM

	topProcesses := []map[string]interface{}{}
	rows, err := db.Query(`SELECT process_name, COUNT(*) as count FROM logs 
		WHERE process_name != '' GROUP BY process_name ORDER BY count DESC LIMIT 10`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			var count int
			rows.Scan(&name, &count)
			topProcesses = append(topProcesses, map[string]interface{}{
				"name":  name,
				"count": count,
			})
		}
	}
	stats["top_processes"] = topProcesses

	last24h := time.Now().Add(-24 * time.Hour)
	var last24hCount int
	db.QueryRow("SELECT COUNT(*) FROM logs WHERE timestamp > ?", last24h).Scan(&last24hCount)
	stats["last_24h_alerts"] = last24hCount

	var whitelistCount int
	db.QueryRow("SELECT COUNT(*) FROM whitelist").Scan(&whitelistCount)
	stats["whitelist_count"] = whitelistCount

	return stats, nil
}

func (db *DB) SearchLogs(keyword string, limit int) ([]LogEntry, error) {
	query := `SELECT id, type, timestamp, alert_type, severity, pid, process_name, message, details, source_ip, dest_ip, dest_port, file_hash, is_new, is_suspicious
		FROM logs WHERE message LIKE ? OR process_name LIKE ? OR details LIKE ? ORDER BY timestamp DESC LIMIT ?`

	searchTerm := "%" + keyword + "%"
	rows, err := db.Query(query, searchTerm, searchTerm, searchTerm, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		var entry LogEntry
		err := rows.Scan(
			&entry.ID,
			&entry.Type,
			&entry.Timestamp,
			&entry.AlertType,
			&entry.Severity,
			&entry.PID,
			&entry.ProcessName,
			&entry.Message,
			&entry.Details,
			&entry.SourceIP,
			&entry.DestIP,
			&entry.DestPort,
			&entry.FileHash,
			&entry.IsNew,
			&entry.IsSuspicious,
		)
		if err != nil {
			continue
		}
		logs = append(logs, entry)
	}

	return logs, nil
}

func (db *DB) GetDailyStats(days int) ([]map[string]interface{}, error) {
	query := `SELECT 
		DATE(timestamp) as date,
		COUNT(*) as total,
		SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
		SUM(CASE WHEN severity = 'warning' THEN 1 ELSE 0 END) as warning,
		SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) as info
		FROM logs 
		WHERE timestamp > datetime('now', '-' || ? || ' days')
		GROUP BY DATE(timestamp)
		ORDER BY date DESC`

	rows, err := db.Query(query, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []map[string]interface{}
	for rows.Next() {
		row := make(map[string]interface{})
		var date string
		var total, critical, warning, info int

		rows.Scan(&date, &total, &critical, &warning, &info)

		row["date"] = date
		row["total"] = total
		row["critical"] = critical
		row["warning"] = warning
		row["info"] = info

		stats = append(stats, row)
	}

	return stats, nil
}

func (db *DB) CleanOldLogs(days int) (int64, error) {
	query := `DELETE FROM logs WHERE timestamp < datetime('now', '-' || ? || ' days')`
	result, err := db.Exec(query, days)
	if err != nil {
		return 0, err
	}

	count, _ := result.RowsAffected()
	log.Printf("Cleaned %d old log entries", count)

	return count, nil
}

func (db *DB) ExportLogs(format string) (string, error) {
	logs, err := db.GetRecentLogs(10000)
	if err != nil {
		return "", err
	}

	if strings.ToLower(format) == "csv" {
		return db.exportToCSV(logs)
	}

	return db.exportToJSON(logs)
}

func (db *DB) exportToJSON(logs []LogEntry) (string, error) {
	var builder strings.Builder
	builder.WriteString("[\n")

	for i, log := range logs {
		if i > 0 {
			builder.WriteString(",\n")
		}
		builder.WriteString(fmt.Sprintf(`  {"id":%d,"type":"%s","timestamp":"%s","alert_type":"%s","severity":"%s","pid":%d,"process_name":"%s","message":"%s"}`,
			log.ID, log.Type, log.Timestamp.Format(time.RFC3339), log.AlertType, log.Severity, log.PID, log.ProcessName, log.Message))
	}

	builder.WriteString("\n]")
	return builder.String(), nil
}

func (db *DB) exportToCSV(logs []LogEntry) (string, error) {
	var builder strings.Builder
	builder.WriteString("ID,Type,Timestamp,AlertType,Severity,PID,ProcessName,Message,Details\n")

	for _, log := range logs {
		builder.WriteString(fmt.Sprintf("%d,%s,%s,%s,%s,%d,%s,%s,%s\n",
			log.ID, log.Type, log.Timestamp.Format(time.RFC3339), log.AlertType, log.Severity,
			log.PID, log.ProcessName, log.Message, log.Details))
	}

	return builder.String(), nil
}
