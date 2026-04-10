package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go-firewall/database"
)

type ProcessInfo struct {
	PID          int32
	Name         string
	CommandLine  string
	ExePath      string
	User         string
	RAMMB        float64
	CPUPercent   float64
	NumFDs       int
	StartTime    time.Time
	FileHash     string
	IsNew        bool
	IsSuspicious bool
	Severity     string
	AlertType    string
}

type ProcessMonitor struct {
	db              *database.DB
	knownProcesses  map[int32]*ProcessInfo
	mu              sync.RWMutex
	stopChan        chan struct{}
	highRAMLimit    float64
	maxInstances    int
	knownHashes     map[string]string
	whitelistHashes map[string]bool
}

func NewProcessMonitor(db *database.DB) *ProcessMonitor {
	return &ProcessMonitor{
		db:              db,
		knownProcesses:  make(map[int32]*ProcessInfo),
		stopChan:        make(chan struct{}),
		highRAMLimit:    1000,
		maxInstances:    5,
		knownHashes:     make(map[string]string),
		whitelistHashes: make(map[string]bool),
	}
}

func (pm *ProcessMonitor) Start() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	pm.scanProcesses()

	for {
		select {
		case <-pm.stopChan:
			return
		case <-ticker.C:
			pm.scanProcesses()
		}
	}
}

func (pm *ProcessMonitor) Stop() {
	close(pm.stopChan)
}

func (pm *ProcessMonitor) scanProcesses() {
	procs, err := pm.getAllProcesses()
	if err != nil {
		log.Printf("Error scanning processes: %v", err)
		return
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	currentPIDs := make(map[int32]bool)
	processCounts := make(map[string]int)

	for _, proc := range procs {
		currentPIDs[proc.PID] = true

		_, exists := pm.knownProcesses[proc.PID]

		if !exists {
			proc.IsNew = true
			proc.IsSuspicious = pm.isProcessSuspicious(&proc)
			pm.knownProcesses[proc.PID] = &proc
			pm.logProcess(&proc)
		} else {
			if proc.RAMMB > pm.highRAMLimit {
				proc.IsSuspicious = true
				proc.AlertType = "HIGH_RAM"
				proc.Severity = "warning"
				pm.logProcess(&proc)
			}
			pm.knownProcesses[proc.PID] = &proc
		}

		processCounts[proc.Name]++
	}

	for name, count := range processCounts {
		if count > pm.maxInstances {
			pm.logMultiInstance(name, count)
		}
	}

	for pid := range pm.knownProcesses {
		if !currentPIDs[pid] {
			delete(pm.knownProcesses, pid)
		}
	}
}

func (pm *ProcessMonitor) getAllProcesses() ([]ProcessInfo, error) {
	var processes []ProcessInfo

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		var pid int32
		if _, err := fmt.Sscanf(pidStr, "%d", &pid); err != nil {
			continue
		}

		if pid == 0 || pid == 2 {
			continue
		}

		proc := pm.getProcessInfo(pid)
		if proc.Name != "" {
			processes = append(processes, proc)
		}
	}

	return processes, nil
}

func (pm *ProcessMonitor) getProcessInfo(pid int32) ProcessInfo {
	procPath := fmt.Sprintf("/proc/%d", pid)

	info := ProcessInfo{
		PID: pid,
	}

	if data, err := os.ReadFile(filepath.Join(procPath, "comm")); err == nil {
		info.Name = strings.TrimSpace(string(data))
	}

	if data, err := os.ReadFile(filepath.Join(procPath, "cmdline")); err == nil {
		info.CommandLine = strings.ReplaceAll(string(data), "\x00", " ")
		info.CommandLine = strings.TrimSpace(info.CommandLine)
	}

	if exe, err := os.Readlink(filepath.Join(procPath, "exe")); err == nil {
		info.ExePath = exe
		info.FileHash = pm.calculateFileHash(exe)
	}

	if stat, err := os.ReadFile(filepath.Join(procPath, "status")); err == nil {
		lines := strings.Split(string(stat), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "VmRSS:") {
				var memKB int
				fmt.Sscanf(line, "VmRSS:%d kB", &memKB)
				info.RAMMB = float64(memKB) / 1024
			}
		}
	}

	if statm, err := os.ReadFile(filepath.Join(procPath, "statm")); err == nil {
		var size, resident int
		fmt.Sscanf(string(statm), "%d %d", &size, &resident)
		info.RAMMB = float64(resident) * 4 / 1024
	}

	if stat, err := os.ReadFile(filepath.Join(procPath, "stat")); err == nil {
		parts := strings.Split(string(stat), " ")
		if len(parts) > 19 {
			var utime, stime int64
			fmt.Sscanf(parts[13], "%d", &utime)
			fmt.Sscanf(parts[14], "%d", &stime)
			info.CPUPercent = float64(utime+stime) / 100
		}
	}

	if fds, err := os.ReadDir(filepath.Join(procPath, "fd")); err == nil {
		info.NumFDs = len(fds)
	}

	return info
}

func (pm *ProcessMonitor) calculateFileHash(path string) string {
	if _, exists := pm.whitelistHashes[path]; exists {
		return ""
	}

	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}

	hashStr := hex.EncodeToString(hash.Sum(nil))

	if threat, exists := pm.knownHashes[hashStr]; exists {
		return threat
	}

	return hashStr
}

func (pm *ProcessMonitor) isProcessSuspicious(proc *ProcessInfo) bool {
	if proc.Name == "" || proc.CommandLine == "" {
		return true
	}

	suspiciousNames := []string{
		"xmrig", "miner", "cryptonight", "stratum",
		"watchdog", "payload", "shellcode",
	}

	lowerName := strings.ToLower(proc.Name)
	for _, susp := range suspiciousNames {
		if strings.Contains(lowerName, susp) {
			proc.AlertType = "MALICIOUS_NAME"
			proc.Severity = "critical"
			return true
		}
	}

	if proc.ExePath != "" {
		hash := pm.calculateFileHash(proc.ExePath)
		if _, exists := pm.knownHashes[hash]; exists {
			proc.AlertType = "KNOWN_THREAT"
			proc.Severity = "critical"
			proc.FileHash = hash
			return true
		}
	}

	if proc.RAMMB > pm.highRAMLimit {
		proc.AlertType = "HIGH_RAM"
		proc.Severity = "warning"
		return true
	}

	if !strings.HasPrefix(proc.ExePath, "/usr") &&
		!strings.HasPrefix(proc.ExePath, "/bin") &&
		!strings.HasPrefix(proc.ExePath, "/sbin") &&
		!strings.HasPrefix(proc.ExePath, "/lib") &&
		proc.ExePath != "" {
		proc.AlertType = "UNKNOWN_ORIGIN"
		proc.Severity = "info"
		return true
	}

	return false
}

func (pm *ProcessMonitor) logProcess(proc *ProcessInfo) {
	logEntry := &database.LogEntry{
		Type:        "PROCESS",
		AlertType:   proc.AlertType,
		Severity:    proc.Severity,
		PID:         proc.PID,
		ProcessName: proc.Name,
		Message: fmt.Sprintf("Process: %s (PID: %d) - %s",
			proc.Name, proc.PID, proc.AlertType),
		Details: fmt.Sprintf("RAM: %.2f MB | CPU: %.2f%% | Path: %s | Hash: %s",
			proc.RAMMB, proc.CPUPercent, proc.ExePath, proc.FileHash),
		SourceIP:     "",
		DestIP:       "",
		DestPort:     0,
		FileHash:     proc.FileHash,
		IsNew:        proc.IsNew,
		IsSuspicious: proc.IsSuspicious,
	}

	if err := pm.db.InsertLog(logEntry); err != nil {
		log.Printf("Failed to insert log: %v", err)
	}

	if proc.IsNew || proc.IsSuspicious {
		log.Printf("[%s] %s: %s (PID: %d, RAM: %.2f MB, Path: %s)",
			proc.Severity, proc.AlertType, proc.Name, proc.PID, proc.RAMMB, proc.ExePath)
	}
}

func (pm *ProcessMonitor) logMultiInstance(name string, count int) {
	logEntry := &database.LogEntry{
		Type:        "PROCESS",
		AlertType:   "MULTI_INSTANCE",
		Severity:    "warning",
		ProcessName: name,
		Message: fmt.Sprintf("Process %s has %d running instances (limit: %d)",
			name, count, pm.maxInstances),
		Details: fmt.Sprintf("Instance count: %d", count),
	}

	if err := pm.db.InsertLog(logEntry); err != nil {
		log.Printf("Failed to insert log: %v", err)
	}

	log.Printf("[WARNING] MULTI_INSTANCE: %s has %d instances", name, count)
}

func (pm *ProcessMonitor) GetProcessList() []ProcessInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	result := make([]ProcessInfo, 0, len(pm.knownProcesses))
	for _, proc := range pm.knownProcesses {
		result = append(result, *proc)
	}
	return result
}

func (pm *ProcessMonitor) GetSuspiciousProcesses() []ProcessInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var result []ProcessInfo
	for _, proc := range pm.knownProcesses {
		if proc.IsSuspicious {
			result = append(result, *proc)
		}
	}
	return result
}

func (pm *ProcessMonitor) GetHighRAMProcesses() []ProcessInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var result []ProcessInfo
	for _, proc := range pm.knownProcesses {
		if proc.RAMMB > pm.highRAMLimit {
			result = append(result, *proc)
		}
	}
	return result
}

func (pm *ProcessMonitor) GetProcessStats() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := map[string]interface{}{
		"total_processes":  len(pm.knownProcesses),
		"suspicious_count": 0,
		"high_ram_count":   0,
		"avg_ram":          0.0,
		"max_ram":          0.0,
		"process_counts":   make(map[string]int),
	}

	var totalRAM float64
	for _, proc := range pm.knownProcesses {
		if proc.IsSuspicious {
			stats["suspicious_count"] = (stats["suspicious_count"]).(int) + 1
		}
		if proc.RAMMB > pm.highRAMLimit {
			stats["high_ram_count"] = (stats["high_ram_count"]).(int) + 1
		}
		if proc.RAMMB > stats["max_ram"].(float64) {
			stats["max_ram"] = proc.RAMMB
		}
		totalRAM += proc.RAMMB
		stats["process_counts"].(map[string]int)[proc.Name]++
	}

	if len(pm.knownProcesses) > 0 {
		stats["avg_ram"] = totalRAM / float64(len(pm.knownProcesses))
	}

	return stats
}

func (pm *ProcessMonitor) ScanFile(filePath string) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"path":   filePath,
		"exists": false,
	}

	info, err := os.Stat(filePath)
	if err != nil {
		result["error"] = err.Error()
		return result, err
	}

	result["exists"] = true
	result["size"] = info.Size()
	result["modified"] = info.ModTime()

	file, err := os.Open(filePath)
	if err != nil {
		result["error"] = err.Error()
		return result, err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		result["error"] = err.Error()
		return result, err
	}

	hashStr := hex.EncodeToString(hash.Sum(nil))
	result["sha256"] = hashStr

	if threat, exists := pm.knownHashes[hashStr]; exists {
		result["threat"] = threat
		result["is_malicious"] = true
	} else {
		result["is_malicious"] = false
	}

	return result, nil
}

func (pm *ProcessMonitor) GetKnownHashesJSON() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	data, _ := json.Marshal(pm.knownHashes)
	return string(data)
}

func (pm *ProcessMonitor) AddToWhitelist(hash string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.whitelistHashes[hash] = true
}

func (pm *ProcessMonitor) SetRAMLimit(limit float64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.highRAMLimit = limit
}
