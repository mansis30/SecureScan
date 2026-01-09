

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	
)

// Terminal color codes
const (
	RED   = "\033[91m"
	GREEN = "\033[92m"
	BLUE  = "\033[94m"
	CYAN  = "\033[96m"
	RESET = "\033[0m"
)

// Clear the terminal screen
func clearTerminal() {
	cmd := "clear"
	if runtime.GOOS == "windows" {
		cmd = "cls"
	}
	exec.Command(cmd).Run()
}

// Display the banner
func displayBanner() {
	fmt.Printf("%s===============================\n", GREEN)
	fmt.Println("          SecureScan            ")
	fmt.Println("      made by Mansi Singh   ")
	fmt.Printf("===============================\n%s\n", RESET)
}

// Get system info (OS, version, architecture, hostname, IPs)
func getSystemInfo() string {
	hostname, _ := os.Hostname()
	ipList, err := net.LookupIP(hostname)
	localIP := "Not found"
	for _, ip := range ipList {
		if ipv4 := ip.To4(); ipv4 != nil {
			localIP = ipv4.String()
			break
		}
	}

	// External IP
	resp, err := http.Get("https://api.ipify.org")
	externalIP := "Could not retrieve external IP"
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		externalIP = string(buf[:n])
	}

	info := fmt.Sprintf(
		"System: %s (%s)\nHostname: %s\nLocal IP Address: %s\nExternal IP Address: %s",
		runtime.GOOS,
		runtime.GOARCH,
		hostname,
		localIP,
		externalIP,
	)
	return info
}

// Validate and format the URL
func validateURL(input string) (string, bool) {
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "https://" + input
	}
	u, err := url.ParseRequestURI(input)
	if err != nil || !u.IsAbs() {
		fmt.Printf("%sInvalid URL format. Please enter a valid URL.%s\n", RED, RESET)
		return "", false
	}
	return input, true
}

// Check SSL certificate validity
func checkSSLCertificate(urlStr string) bool {
	fmt.Printf("\n%sSSL Certificate Check:%s\n", CYAN, RESET)
	u, err := url.Parse(urlStr)
	if err != nil {
		fmt.Printf("%s✗ Invalid URL: %v%s\n", RED, err, RESET)
		return false
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	conn, err := tls.Dial("tcp", host, &tls.Config{})
	if err != nil {
		fmt.Printf("%s✗ SSL Certificate error! %v%s\n", RED, err, RESET)
		return false
	}
	defer conn.Close()
	fmt.Printf("%s✓ SSL Certificate is valid.%s\n", GREEN, RESET)
	return true
}

// Check for important HTTP headers
func checkHTTPHeaders(urlStr string) bool {
	fmt.Printf("\n%sHTTP Headers Security Check:%s\n", CYAN, RESET)
	resp, err := http.Get(urlStr)
	if err != nil {
		fmt.Printf("%s✗ Failed to check headers: %v%s\n", RED, err, RESET)
		return false
	}
	defer resp.Body.Close()

	issuesFound := false
	headers := resp.Header

	headerChecks := map[string]struct {
		ExpectedValue interface{}
		Vulnerability string
	}{
		"X-Content-Type-Options": {
			"nosniff",
			"Missing or incorrect X-Content-Type-Options; may allow MIME-type sniffing.",
		},
		"X-Frame-Options": {
			[]string{"DENY", "SAMEORIGIN"},
			"X-Frame-Options may be vulnerable to clickjacking attacks.",
		},
		"X-XSS-Protection": {
			"1; mode=block",
			"X-XSS-Protection is missing or not set to block mode; may allow cross-site scripting attacks.",
		},
		"Content-Security-Policy": {
			nil,
			"Content-Security-Policy is missing; may allow various attacks, including XSS.",
		},
		"Access-Control-Allow-Origin": {
			nil,
			"Improper CORS configuration may expose the site to cross-origin attacks.",
		},
	}

	for header, check := range headerChecks {
		vals, ok := headers[header]
		if !ok {
			fmt.Printf("%s✗ %s is missing; %s%s\n", RED, header, check.Vulnerability, RESET)
			issuesFound = true
			continue
		}
		value := vals[0]
		switch expected := check.ExpectedValue.(type) {
		case nil:
			// Only presence is required
		case string:
			if value != expected {
				fmt.Printf("%s✗ %s found, but value '%s' may be vulnerable; %s%s\n", RED, header, value, check.Vulnerability, RESET)
				issuesFound = true
			}
		case []string:
			valid := false
			for _, v := range expected {
				if value == v {
					valid = true
				}
			}
			if !valid {
				fmt.Printf("%s✗ %s found, but value '%s' may be vulnerable; %s%s\n", RED, header, value, check.Vulnerability, RESET)
				issuesFound = true
			}
		}
	}
	if !issuesFound {
		fmt.Printf("%s✓ All security headers are properly configured.%s\n", GREEN, RESET)
	}
	return !issuesFound
}

// Basic phishing pattern detection with regex
func checkPhishing(urlStr string) bool {
	fmt.Printf("\n%sPhishing URL Analysis:%s\n", CYAN, RESET)
	patterns := []string{
		"account", "login", "secure", "bank", "update", "confirm", "verify", "expired",
		"password", "admin", "signin", "auth", "validate", "unlock", "urgent", "important",
		"alert", "suspended", "limited", "notice", "access", "recovery", "customer-service",
		"support", "webmail", "email", "mailbox", "new-message", "messages", "helpdesk",
		"billing", "payment", "checkout", "invoice", "account-pay", "paypal", "credit",
		"transfer", "transaction", "secure-login", "auth", "signin", "account-update",
		"-secure-", "-login-", "verify",
	}

	urlLower := strings.ToLower(urlStr)
	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, urlLower)
		if matched {
			fmt.Printf("%s✗ Warning: This URL may be a phishing site based on pattern analysis.%s\n", RED, RESET)
			return false
		}
	}
	fmt.Printf("%s✓ No phishing indicators found.%s\n", GREEN, RESET)
	return true
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the URL to check: ")
	inputURL, _ := reader.ReadString('\n')
	inputURL = strings.TrimSpace(inputURL)

	clearTerminal()
	displayBanner()
	fmt.Printf("%sSystem Information:%s\n", BLUE, RESET)
	fmt.Println(getSystemInfo())

	fmt.Printf("\n%sStarting security checks for the domain: %s...%s\n\n", BLUE, inputURL, RESET)

	validURL, ok := validateURL(inputURL)
	if !ok {
		return
	}
	sslCheck := checkSSLCertificate(validURL)
	headerCheck := checkHTTPHeaders(validURL)
	phishingCheck := checkPhishing(validURL)

	fmt.Println("\n" + strings.Repeat("=", 35))
	if !(sslCheck && headerCheck && phishingCheck) {
		fmt.Printf("%s⚠️ Issues detected. Please review the warnings above.%s\n", RED, RESET)
	} else {
		fmt.Printf("%s✓ Connection Secure; No issues detected.%s\n", GREEN, RESET)
	}
	fmt.Println(strings.Repeat("=", 35))
}

