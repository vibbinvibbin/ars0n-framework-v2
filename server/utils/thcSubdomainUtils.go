package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

type THCSubdomainScanStatus struct {
	ID                string `json:"id"`
	ScanID            string `json:"scan_id"`
	Domain            string `json:"domain"`
	Status            string `json:"status"`
	Result            string `json:"result,omitempty"`
	Error             string `json:"error,omitempty"`
	StdOut            string `json:"stdout,omitempty"`
	StdErr            string `json:"stderr,omitempty"`
	Command           string `json:"command,omitempty"`
	ExecTime          string `json:"execution_time,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	ScopeTargetID     string `json:"scope_target_id"`
	AutoScanSessionID string `json:"auto_scan_session_id,omitempty"`
}

// RunTHCSubdomainScan initiates a THC subdomain download scan
func RunTHCSubdomainScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] Received request to run THC subdomain download scan")
	var requestData struct {
		FQDN              string  `json:"fqdn"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Printf("[ERROR] Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	domain := requestData.FQDN
	wildcardDomain := "*." + domain
	log.Printf("[INFO] Processing THC subdomain scan request for domain: %s", domain)

	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s: %v", domain, err)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[INFO] Found matching scope target ID: %s", scopeTargetID)

	scanID := uuid.New().String()
	log.Printf("[INFO] Generated new scan ID: %s", scanID)

	var insertQuery string
	var args []interface{}
	if requestData.AutoScanSessionID != nil && *requestData.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO thc_subdomain_scans (scan_id, domain, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID, *requestData.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO thc_subdomain_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to create THC subdomain scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[INFO] Successfully created THC subdomain scan record in database")

	go ExecuteAndParseTHCSubdomainScan(scanID, domain)

	log.Printf("[INFO] Initiated THC subdomain scan with ID: %s for domain: %s", scanID, domain)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

// ExecuteAndParseTHCSubdomainScan downloads and processes subdomains from THC API
func ExecuteAndParseTHCSubdomainScan(scanID, domain string) {
	log.Printf("[INFO] Starting THC subdomain download for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	// Perform the HTTP request to THC API
	log.Printf("[INFO] Initiating HTTP request to THC API for subdomains")
	url := fmt.Sprintf("https://ip.thc.org/api/v1/subdomains/download?domain=%s&limit=50000", domain)
	method := "GET"

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		log.Printf("[ERROR] Failed to create HTTP request: %v", err)
		execTime := time.Since(startTime).String()
		UpdateTHCSubdomainScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create request: %v", err), "", execTime)
		return
	}
	req.Header.Add("Accept", "text/csv")

	res, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed to execute HTTP request: %v", err)
		execTime := time.Since(startTime).String()
		UpdateTHCSubdomainScanStatus(scanID, "error", "", fmt.Sprintf("Failed to execute request: %v", err), "", execTime)
		return
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read response body: %v", err)
		execTime := time.Since(startTime).String()
		UpdateTHCSubdomainScanStatus(scanID, "error", "", fmt.Sprintf("Failed to read response: %v", err), "", execTime)
		return
	}

	execTime := time.Since(startTime).String()
	log.Printf("[INFO] THC API request completed in %s", execTime)
	log.Printf("[INFO] Response status code: %d", res.StatusCode)
	log.Printf("[INFO] Response body length: %d bytes", len(body))
	
	// Log first 500 chars of response for debugging
	maxLen := 500
	if len(body) < maxLen {
		maxLen = len(body)
	}
	log.Printf("[INFO] First %d chars of response: %s", maxLen, string(body[:maxLen]))

	// Parse the CSV response
	log.Printf("[INFO] Parsing CSV response from THC API")
	responseBody := string(body)
	lines := strings.Split(responseBody, "\n")
	log.Printf("[INFO] Processing %d lines from THC API response", len(lines))

	// Use a map to handle deduplication
	uniqueSubdomains := make(map[string]bool)
	processedCount := 0
	skippedCount := 0
	for i, line := range lines {
		// Clean the line
		cleanLine := strings.TrimSpace(line)

		// Skip empty lines and header lines
		if cleanLine == "" || strings.Contains(cleanLine, "domain") || strings.HasPrefix(cleanLine, "#") {
			skippedCount++
			continue
		}

		// Remove quotes if present (CSV format)
		cleanLine = strings.Trim(cleanLine, "\"")
		cleanLine = strings.TrimSpace(cleanLine)

		// Log each non-empty line for debugging
		if cleanLine != "" {
			log.Printf("[DEBUG] Line %d: %s", i, cleanLine)
		}

		// Check if the line is a valid subdomain of our target domain
		if cleanLine != "" {
			if strings.HasSuffix(cleanLine, domain) || strings.HasSuffix(cleanLine, "."+domain) {
				log.Printf("[DEBUG] MATCHED: %s for domain %s", cleanLine, domain)
				uniqueSubdomains[cleanLine] = true
				processedCount++
			} else {
				log.Printf("[DEBUG] NOT MATCHED: %s for domain %s (expected to end with %s or .%s)", cleanLine, domain, domain, domain)
			}
		}
	}
	log.Printf("[DEBUG] Processed %d lines, skipped %d lines", processedCount, skippedCount)

	// Convert map keys to slice
	var finalSubdomains []string
	for subdomain := range uniqueSubdomains {
		finalSubdomains = append(finalSubdomains, subdomain)
	}

	// Sort the results for consistency
	sort.Strings(finalSubdomains)

	// Join the results with newlines
	result := strings.Join(finalSubdomains, "\n")
	log.Printf("[INFO] Found %d unique subdomains for domain %s", len(finalSubdomains), domain)
	log.Printf("[INFO] Total result string length: %d bytes", len(result))
	if len(finalSubdomains) > 0 {
		sampleCount := 5
		if len(finalSubdomains) < sampleCount {
			sampleCount = len(finalSubdomains)
		}
		log.Printf("[INFO] Sample subdomains: %v", finalSubdomains[:sampleCount])
	}

	log.Printf("[INFO] Updating scan status in database for scan ID: %s", scanID)
	command := fmt.Sprintf("GET https://ip.thc.org/api/v1/subdomains/download?domain=%s&limit=50000", domain)
	UpdateTHCSubdomainScanStatus(scanID, "success", result, "", command, execTime)

	log.Printf("[INFO] THC subdomain download completed successfully for domain %s (scan ID: %s)", domain, scanID)
	log.Printf("[INFO] Total execution time including processing: %s", time.Since(startTime))
}

// UpdateTHCSubdomainScanStatus updates the scan status in the database
func UpdateTHCSubdomainScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating THC subdomain scan status for scan ID %s to %s", scanID, status)
	query := `UPDATE thc_subdomain_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`

	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)

	if err != nil {
		log.Printf("[ERROR] Failed to update THC subdomain scan status: %v", err)
	} else {
		log.Printf("[INFO] Successfully updated THC subdomain scan status")
	}
}

// GetTHCSubdomainScanStatus retrieves the status of a specific THC subdomain scan
func GetTHCSubdomainScanStatus(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] Received request to get THC subdomain scan status")
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[INFO] Retrieving scan status for scan ID: %s", scanID)

	query := `SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM thc_subdomain_scans WHERE scan_id = $1`

	var scan THCSubdomainScanStatus
	var resultNS, errorNS, stdoutNS, stderrNS, commandNS, execTimeNS, autoSessionNS sql.NullString
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID, &scan.ScanID, &scan.Domain, &scan.Status, &resultNS, &errorNS, &stdoutNS, &stderrNS, &commandNS, &execTimeNS, &scan.CreatedAt, &scan.ScopeTargetID, &autoSessionNS,
	)
	// Convert sql.NullString to regular strings
	if resultNS.Valid {
		scan.Result = resultNS.String
	}
	if errorNS.Valid {
		scan.Error = errorNS.String
	}
	if stdoutNS.Valid {
		scan.StdOut = stdoutNS.String
	}
	if stderrNS.Valid {
		scan.StdErr = stderrNS.String
	}
	if commandNS.Valid {
		scan.Command = commandNS.String
	}
	if execTimeNS.Valid {
		scan.ExecTime = execTimeNS.String
	}
	if autoSessionNS.Valid {
		scan.AutoScanSessionID = autoSessionNS.String
	}

	if err == pgx.ErrNoRows {
		log.Printf("[ERROR] Scan not found: %s", scanID)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("[ERROR] Failed to retrieve scan status: %v", err)
		http.Error(w, "Failed to retrieve scan status", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] Successfully retrieved scan status for ID: %s", scanID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

// GetTHCSubdomainScansForScopeTarget retrieves all THC subdomain scans for a specific scope target
func GetTHCSubdomainScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] Received request to get THC subdomain scans for scope target")
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	log.Printf("[INFO] Retrieving scans for scope target ID: %s", scopeTargetID)

	query := `SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM thc_subdomain_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to retrieve scans: %v", err)
		http.Error(w, "Failed to retrieve scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []THCSubdomainScanStatus
	for rows.Next() {
		var scan THCSubdomainScanStatus
		var resultNS, errorNS, stdoutNS, stderrNS, commandNS, execTimeNS, autoSessionNS sql.NullString
		err := rows.Scan(
			&scan.ID, &scan.ScanID, &scan.Domain, &scan.Status, &resultNS, &errorNS, &stdoutNS, &stderrNS, &commandNS, &execTimeNS, &scan.CreatedAt, &scan.ScopeTargetID, &autoSessionNS,
		)
		// Convert sql.NullString to regular strings
		if resultNS.Valid {
			scan.Result = resultNS.String
		}
		if errorNS.Valid {
			scan.Error = errorNS.String
		}
		if stdoutNS.Valid {
			scan.StdOut = stdoutNS.String
		}
		if stderrNS.Valid {
			scan.StdErr = stderrNS.String
		}
		if commandNS.Valid {
			scan.Command = commandNS.String
		}
		if execTimeNS.Valid {
			scan.ExecTime = execTimeNS.String
		}
		if autoSessionNS.Valid {
			scan.AutoScanSessionID = autoSessionNS.String
		}
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			http.Error(w, "Failed to scan rows", http.StatusInternalServerError)
			return
		}
		scans = append(scans, scan)
	}

	log.Printf("[INFO] Successfully retrieved %d scans for scope target ID: %s", len(scans), scopeTargetID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}
