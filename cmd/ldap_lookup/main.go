package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"llm_api_monitor/internal/ldapad"
)

func main() {
	var (
		ldapURL        = flag.String("url", env("LDAP_URL", "ldap://10.20.3.85:389"), "LDAP URL")
		bindDN         = flag.String("bind-dn", env("LDAP_BIND_DN", ""), "LDAP bind DN or UPN")
		bindPassword   = flag.String("bind-password", env("LDAP_BIND_PASSWORD", ""), "LDAP bind password")
		baseDN         = flag.String("base-dn", env("LDAP_BASE_DN", "DC=xmfunny,DC=com"), "LDAP base DN")
		userBaseDN     = flag.String("user-base-dn", env("LDAP_USER_BASE_DN", ""), "LDAP user base DN")
		computerBaseDN = flag.String("computer-base-dn", env("LDAP_COMPUTER_BASE_DN", ""), "LDAP computer base DN")
		username       = flag.String("user", "", "sAMAccountName to query")
		host           = flag.String("host", "", "computer host/cn/dNSHostName to query")
		timeout        = flag.Duration("timeout", 5*time.Second, "LDAP timeout")
	)
	flag.Parse()

	if *bindDN == "" || *bindPassword == "" {
		log.Fatal("bind-dn and bind-password are required")
	}

	client, err := ldapad.New(ldapad.Config{
		URL:            *ldapURL,
		BindDN:         *bindDN,
		BindPassword:   *bindPassword,
		BaseDN:         *baseDN,
		UserBaseDN:     *userBaseDN,
		ComputerBaseDN: *computerBaseDN,
		Timeout:        *timeout,
	})
	if err != nil {
		log.Fatalf("create ldap client failed: %v", err)
	}

	result, err := client.Match(*username, *host)
	if err != nil {
		log.Fatalf("ldap match failed: %v", err)
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("marshal result failed: %v", err)
	}
	fmt.Println(string(data))
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
