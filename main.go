package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/oschwald/geoip2-golang"
)

const (
	port                 = "8080"
	rateLimitPerMinute   = 60
	banDuration          = 24 * time.Hour
	logFile              = "attack_logs.txt"
	countryBlockList     = "CN,RU,IR"
	bucketCapacity       = 10000
	bucketRefillRate     = 100
	sessionCookieName    = "admin_session"
	sessionSecretKey     = "your-secret-key" // Change this to a secure key
	adminUsername        = "Admin"
	adminPassword        = "Admin"
)

var (
	mu                sync.Mutex
	requestCounts     = make(map[string]int)
	bannedIPs         = make(map[string]time.Time)
	tokenBucket       = make(map[string]int)
	attackStatistics  = make(map[string]int)
	adminLogs         = make([]string, 0)
	geoIPDB           *geoip2.Reader
	store             = sessions.NewCookieStore([]byte(sessionSecretKey))
)

type AttackStat struct {
	IP              string `json:"ip"`
	RequestCount    int    `json:"request_count"`
	BannedUntil     string `json:"banned_until,omitempty"`
	DetectedAttack  string `json:"detected_attack,omitempty"`
	GeoLocation     string `json:"geo_location,omitempty"`
	LastRequestTime string `json:"last_request_time"`
}

func init() {
	var err error
	geoIPDB, err = geoip2.Open("GeoLite2-Country.mmdb")
	if err != nil {
		log.Fatalf("Could not load GeoIP database: %v", err)
	}

	logFileHandle, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening log file: %v", err)
	}
	log.SetOutput(logFileHandle)

	go refillTokenBuckets()
	go resetRateLimits()
	go clearExpiredBans()
}

func refillTokenBuckets() {
	for {
		time.Sleep(time.Second)
		mu.Lock()
		for ip := range tokenBucket {
			tokenBucket[ip] = min(tokenBucket[ip]+bucketRefillRate, bucketCapacity)
		}
		mu.Unlock()
	}
}

func resetRateLimits() {
	for {
		time.Sleep(time.Minute)
		mu.Lock()
		requestCounts = make(map[string]int)
		mu.Unlock()
	}
}

func clearExpiredBans() {
	for {
		time.Sleep(5 * time.Minute)
		mu.Lock()
		for ip, expiry := range bannedIPs {
			if time.Now().After(expiry) {
				delete(bannedIPs, ip)
			}
		}
		mu.Unlock()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	mu.Lock()
	banExpiry, isBanned := bannedIPs[clientIP]
	mu.Unlock()
	if isBanned && time.Now().Before(banExpiry) {
		http.Error(w, "Access denied. Your IP is banned due to suspicious activity.", http.StatusForbidden)
		return
	}

	country := lookupGeoIP(clientIP)
	if isCountryBlocked(country) {
		logAttack(clientIP, "Country blocked")
		http.Error(w, "Your country is blocked from accessing this server.", http.StatusForbidden)
		return
	}

	mu.Lock()
	if tokenBucket[clientIP] > 0 {
		tokenBucket[clientIP]--
		requestCounts[clientIP]++
		if requestCounts[clientIP] > rateLimitPerMinute {
			bannedIPs[clientIP] = time.Now().Add(banDuration)
			logAttack(clientIP, "Rate limit exceeded")
			mu.Unlock()
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	} else {
		bannedIPs[clientIP] = time.Now().Add(banDuration)
		logAttack(clientIP, "Rate limit exceeded")
		mu.Unlock()
		http.Error(w, "Too many requests, rate limit exceeded.", http.StatusTooManyRequests)
		return
	}
	mu.Unlock()

	fmt.Fprintf(w, "Request successful from %s\n", clientIP)
}

func lookupGeoIP(ip string) string {
	parsedIP := net.ParseIP(ip)
	record, err := geoIPDB.Country(parsedIP)
	if err != nil {
		return "Unknown"
	}
	return record.Country.IsoCode
}

func isCountryBlocked(country string) bool {
	blockedCountries := strings.Split(countryBlockList, ",")
	for _, blocked := range blockedCountries {
		if country == blocked {
			return true
		}
	}
	return false
}

func logAttack(ip, reason string) {
	mu.Lock()
	defer mu.Unlock()
	log.Printf("Attack detected from IP: %s, Reason: %s", ip, reason)
	attackStatistics[ip]++
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	stats := make([]AttackStat, 0, len(attackStatistics))
	for ip, count := range attackStatistics {
		bannedUntil := ""
		if expiry, banned := bannedIPs[ip]; banned {
			bannedUntil = expiry.String()
		}
		geoLoc := lookupGeoIP(ip)
		stats = append(stats, AttackStat{
			IP:             ip,
			RequestCount:   count,
			BannedUntil:    bannedUntil,
			DetectedAttack: "DDoS attempt",
			GeoLocation:    geoLoc,
			LastRequestTime: time.Now().String(),
		})
	}
	response, _ := json.Marshal(stats)
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func logAdminAction(action string) {
	mu.Lock()
	defer mu.Unlock()
	adminLogs = append(adminLogs, fmt.Sprintf("%s: %s", time.Now().Format(time.RFC3339), action))
}

func adminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == adminUsername && password == adminPassword {
			session, _ := store.Get(r, sessionCookieName)
			session.Values["authenticated"] = true
			session.Save(r, w)
			http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
			logAdminAction("Admin logged in")
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	http.ServeFile(w, r, "static/admin_login.html")
}

func adminDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, sessionCookieName)
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	http.ServeFile(w, r, "static/admin_dashboard.html")
}

func publicDashboard(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/public_dashboard.html")
}

func handleAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, sessionCookieName)
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func handleAdminLogs(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	response, _ := json.Marshal(adminLogs)
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, sessionCookieName)
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		newUsername := r.FormValue("username")
		// newPassword is not used here, so it's removed
		// Ideally, you would save the new user securely to a database here.
		// For demonstration purposes, we'll just log it.
		logAdminAction(fmt.Sprintf("Created new admin user: %s", newUsername))
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
		return
	}
	http.ServeFile(w, r, "static/create_user.html")
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, sessionCookieName)
	session.Options.MaxAge = -1 // delete the session cookie
	session.Save(r, w)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
	logAdminAction("Admin logged out")
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", publicDashboard)
	r.HandleFunc("/stats", handleStats)
	r.HandleFunc("/admin/login", adminLogin)
	r.HandleFunc("/admin/dashboard", handleAuth(adminDashboard))
	r.HandleFunc("/admin/create_user", handleAuth(handleCreateUser))
	r.HandleFunc("/admin/logs", handleAuth(handleAdminLogs))
	r.HandleFunc("/admin/logout", handleLogout)

	http.Handle("/", r)
	log.Printf("Server started on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
