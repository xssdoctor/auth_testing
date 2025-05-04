package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"gorm.io/datatypes"
	"gorm.io/driver/postgres"
)

type SavedRequest struct {
    ID        uint           `gorm:"primaryKey"`
    Method    string
    Scheme    string
    Host      string
    Path      string
    Query     string
    Headers   datatypes.JSON
    Body      string
    CreatedAt time.Time
}

type Server struct {
    db *gorm.DB
}

type ReceivePayload struct {
    Data string `json:"data"`
}

func main() {
    mode := flag.String("mode", "serve", "Mode: serve | replay")
    cookies := flag.String("cookies", "", "Cookie string for replay")
    csrf := flag.String("csrf", "", "CSRF token for replay")
    proxyAddr := flag.String("proxy", "http://127.0.0.1:8080", "Proxy address (Burp/Caido)")
    flag.Parse()

    // Configure more verbose logging
    log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
    log.Println("Starting application")

    dsn := os.Getenv("DATABASE_URL")
    if dsn == "" {
        log.Fatal("DATABASE_URL env var is required")
    }
    log.Printf("Using database connection string: %s", dsn)

    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
    if err != nil {
        log.Fatalf("failed to connect database: %v", err)
    }
    log.Println("Successfully connected to database")

    // Log the database schema being created
    log.Println("Running AutoMigrate to create/update SavedRequest table")
    if err := db.AutoMigrate(&SavedRequest{}); err != nil {
        log.Fatalf("auto-migrate failed: %v", err)
    }
    log.Println("AutoMigrate completed successfully")

    // Verify table exists by executing a query
    var count int64
    if err := db.Model(&SavedRequest{}).Count(&count).Error; err != nil {
        log.Fatalf("Failed to query SavedRequest table: %v", err)
    }
    log.Printf("SavedRequest table exists and contains %d records", count)

    switch *mode {
    case "serve":
        runServer(db)
    case "replay":
        runReplay(db, *cookies, *csrf, *proxyAddr)
    default:
        fmt.Println("Invalid mode")
        os.Exit(1)
    }
}

func runServer(db *gorm.DB) {
    srv := &Server{db: db}
    mux := http.NewServeMux()
    mux.HandleFunc("/receive", srv.handleReceive)

    addr := ":8081" // change if needed
    log.Printf("Listening on %s", addr)
    if err := http.ListenAndServe(addr, mux); err != nil {
        log.Fatalf("server error: %v", err)
    }
}

func (s *Server) handleReceive(w http.ResponseWriter, r *http.Request) {
    requestID := time.Now().UnixNano()
    log.Printf("[%d] 🔍 Request received: %s %s", requestID, r.Method, r.URL.Path)
    log.Printf("[%d] Content-Type: %s, Content-Length: %d", requestID, r.Header.Get("Content-Type"), r.ContentLength)
    
    if r.Method != http.MethodPost {
        log.Printf("[%d] ❌ Method not allowed: %s", requestID, r.Method)
        http.Error(w, "POST only", http.StatusMethodNotAllowed)
        return
    }

    bodyBytes, err := io.ReadAll(r.Body)
    if err != nil {
        log.Printf("[%d] ❌ Failed to read request body: %v", requestID, err)
        http.Error(w, "Failed to read body", http.StatusBadRequest)
        return
    }
    r.Body.Close()
    r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
    
    log.Printf("[%d] 📦 Raw request body: %s", requestID, string(bodyBytes))

    var payload ReceivePayload
    if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
        log.Printf("[%d] ❌ Failed to parse JSON: %v", requestID, err)
        http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
        return
    }
    log.Printf("[%d] 📝 Received payload with data length=%d", requestID, len(payload.Data))

    // If payload data is too large, log just the beginning
    if len(payload.Data) > 100 {
        log.Printf("[%d] 📝 Data begins with: %s...", requestID, payload.Data[:100])
    } else {
        log.Printf("[%d] 📝 Data: %s", requestID, payload.Data)
    }

    decoded, err := base64.StdEncoding.DecodeString(payload.Data)
    if err != nil {
        log.Printf("[%d] ❌ Base64 decode failed: %v", requestID, err)
        http.Error(w, "invalid base64: "+err.Error(), http.StatusBadRequest)
        return
    }
    log.Printf("[%d] 🔓 Base64 decoded, raw length=%d", requestID, len(decoded))

    sr, err := parseRawHTTP(string(decoded))
    if err != nil {
        log.Printf("[%d] ❌ Failed to parse HTTP: %v", requestID, err)
        http.Error(w, "parse error: "+err.Error(), http.StatusBadRequest)
        return
    }
    log.Printf("[%d] 🔎 Parsed HTTP request: %s %s %s", requestID, sr.Method, sr.Host, sr.Path)
    
    // Log the parsed request details
    headersJSON, _ := json.MarshalIndent(sr.Headers, "", "  ")
    log.Printf("[%d] 📋 Headers: %s", requestID, string(headersJSON))
    if len(sr.Body) > 100 {
        log.Printf("[%d] 📋 Body begins with: %s...", requestID, sr.Body[:100])
    } else if sr.Body != "" {
        log.Printf("[%d] 📋 Body: %s", requestID, sr.Body)
    }

    // Get SQL logger
    sqlDB, err := s.db.DB()
    if err != nil {
        log.Printf("[%d] ❌ Failed to get database connection: %v", requestID, err)
        http.Error(w, "database connection error", http.StatusInternalServerError)
        return
    }
    
    // Test database connection
    if err := sqlDB.Ping(); err != nil {
        log.Printf("[%d] ❌ Database ping failed: %v", requestID, err)
        http.Error(w, "database connection error: "+err.Error(), http.StatusInternalServerError)
        return
    }
    log.Printf("[%d] ✓ Database connection verified", requestID)

    // Check if request already exists in database
    var existingRequest SavedRequest
    result := s.db.Where("method = ? AND host = ? AND path = ?", sr.Method, sr.Host, sr.Path).First(&existingRequest)
    
    if result.Error == nil {
        // Request exists, update it
        log.Printf("[%d] 🔄 Found existing request with ID=%d, updating instead of creating new", 
            requestID, existingRequest.ID)
        
        // Update existing record
        sr.ID = existingRequest.ID // Keep the same ID
        updateResult := s.db.Save(sr)
        
        if updateResult.Error != nil {
            log.Printf("[%d] ❌ DB update error: %v", requestID, updateResult.Error)
            http.Error(w, "db error: "+updateResult.Error.Error(), http.StatusInternalServerError)
            return
        }
        
        log.Printf("[%d] ✅ Updated existing request: ID=%d, Method=%s, Host=%s, Path=%s, RowsAffected=%d", 
            requestID, sr.ID, sr.Method, sr.Host, sr.Path, updateResult.RowsAffected)
    } else if result.Error == gorm.ErrRecordNotFound {
        // Request doesn't exist, create a new one
        log.Printf("[%d] 💾 Request doesn't exist, creating new record", requestID)
        
        createResult := s.db.Create(sr)
        if createResult.Error != nil {
            log.Printf("[%d] ❌ DB create error: %v", requestID, createResult.Error)
            log.Printf("[%d] ℹ️ Rows affected: %d", requestID, createResult.RowsAffected)
            http.Error(w, "db error: "+createResult.Error.Error(), http.StatusInternalServerError)
            return
        }
        
        log.Printf("[%d] ✅ Created new request: ID=%d, Method=%s, Host=%s, Path=%s, RowsAffected=%d", 
            requestID, sr.ID, sr.Method, sr.Host, sr.Path, createResult.RowsAffected)
    } else {
        // Error occurred during search
        log.Printf("[%d] ❌ DB search error: %v", requestID, result.Error)
        http.Error(w, "db error: "+result.Error.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    fmt.Fprintln(w, "saved")
}

func runReplay(db *gorm.DB, cookies, csrf, proxyAddr string) {
    var requests []SavedRequest
    if err := db.Find(&requests).Error; err != nil {
        log.Fatalf("db read error: %v", err)
    }

    proxyURL, _ := url.Parse(proxyAddr)
    transport := &http.Transport{
        Proxy: http.ProxyURL(proxyURL),
        TLSClientConfig: &tls.Config{ // ignore TLS for quick testing via proxy
            InsecureSkipVerify: true,
        },
        DialContext: (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
    }
    client := &http.Client{Transport: transport, Timeout: 60 * time.Second}

    for _, sr := range requests {
        reqURL := fmt.Sprintf("%s://%s%s", sr.Scheme, sr.Host, sr.Path)
        if sr.Query != "" {
            reqURL += "?" + sr.Query
        }

        var body io.Reader
        if sr.Body != "" {
            body = strings.NewReader(sr.Body)
        }

        req, err := http.NewRequest(sr.Method, reqURL, body)
        if err != nil {
            log.Printf("request build error for %d: %v", sr.ID, err)
            continue
        }

        // Copy original headers
        var hdrs map[string]string
        json.Unmarshal(sr.Headers, &hdrs)
        for k, v := range hdrs {
            req.Header.Set(k, v)
        }

        // Override cookies if provided
        if cookies != "" {
            req.Header.Set("Cookie", cookies)
        }

        // Override CSRF token headers if provided - only if they already exist in the original request
        if csrf != "" {
            for name := range req.Header {
                if strings.Contains(strings.ToLower(name), "csrf") {
                    req.Header.Set(name, csrf)
                }
            }
        }

        resp, err := client.Do(req)
        if err != nil {
            log.Printf("http error for %d: %v", sr.ID, err)
            continue
        }
        io.Copy(io.Discard, resp.Body)
        resp.Body.Close()

        if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
            log.Printf("%s %s => %d", sr.Method, sr.Path, resp.StatusCode)
        }
    }
}

func parseRawHTTP(raw string) (*SavedRequest, error) {
    log.Printf("🔍 Parsing raw HTTP: %d bytes", len(raw))
    if len(raw) > 100 {
        log.Printf("🔍 Request begins with: %s...", raw[:100])
    }
    
    reader := bufio.NewReader(strings.NewReader(raw))
    line, err := reader.ReadString('\n')
    if err != nil {
        log.Printf("❌ Unable to read request line: %v", err)
        return nil, fmt.Errorf("unable to read request line: %w", err)
    }
    line = strings.TrimSpace(line)
    log.Printf("🔍 Request line: %s", line)
    
    parts := strings.SplitN(line, " ", 3)
    if len(parts) < 3 {
        log.Printf("❌ Malformed request line: %s", line)
        return nil, fmt.Errorf("malformed request line")
    }
    method := parts[0]
    target := parts[1]

    path := target
    query := ""
    if idx := strings.Index(target, "?"); idx != -1 {
        path = target[:idx]
        query = target[idx+1:]
    }
    log.Printf("🔍 Parsed method=%s, path=%s, query=%s", method, path, query)

    headers := make(map[string]string)
    host := ""
    scheme := "https"

    log.Printf("🔍 Parsing headers")
    for {
        hline, err := reader.ReadString('\n')
        if err != nil {
            log.Printf("❌ Error reading headers: %v", err)
            return nil, fmt.Errorf("reading headers: %w", err)
        }
        hline = strings.TrimRight(hline, "\r\n")
        if hline == "" {
            log.Printf("🔍 End of headers")
            break // end headers
        }
        kv := strings.SplitN(hline, ":", 2)
        if len(kv) != 2 {
            log.Printf("⚠️ Skipping malformed header: %s", hline)
            continue
        }
        name := strings.TrimSpace(kv[0])
        value := strings.TrimSpace(kv[1])
        headers[name] = value
        log.Printf("🔍 Header: %s: %s", name, value)
        if strings.EqualFold(name, "Host") {
            host = value
            log.Printf("🔍 Found Host header: %s", host)
        }
    }

    bodyBuf := new(bytes.Buffer)
    bytesRead, err := io.Copy(bodyBuf, reader)
    if err != nil {
        log.Printf("⚠️ Error reading body: %v", err)
    }
    log.Printf("🔍 Read body: %d bytes", bytesRead)
    body := bodyBuf.String()

    hdrJSON, _ := json.Marshal(headers)
    log.Printf("🔍 Marshalled headers to JSON: %d bytes", len(hdrJSON))
    
    sr := &SavedRequest{
        Method:  method,
        Scheme:  scheme,
        Host:    host,
        Path:    path,
        Query:   query,
        Headers: datatypes.JSON(hdrJSON),
        Body:    body,
    }
    log.Printf("✅ Successfully parsed HTTP request")
    return sr, nil
}
