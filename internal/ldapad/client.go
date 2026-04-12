package ldapad

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const UnknownValue = "unknow"

type Config struct {
	URL            string
	BindDN         string
	BindPassword   string
	BaseDN         string
	UserBaseDN     string
	ComputerBaseDN string
	Timeout        time.Duration
	Insecure       bool
}

type Client struct {
	cfg Config
}

type UserInfo struct {
	DN                string   `json:"dn"`
	CN                string   `json:"cn"`
	DisplayName       string   `json:"display_name"`
	SAMAccountName    string   `json:"sam_account_name"`
	UserPrincipalName string   `json:"user_principal_name"`
	Mail              string   `json:"mail"`
	Department        string   `json:"department"`
	Company           string   `json:"company"`
	Title             string   `json:"title"`
	TelephoneNumber   string   `json:"telephone_number"`
	Mobile            string   `json:"mobile"`
	Description       string   `json:"description"`
	MemberOf          []string `json:"member_of"`
	WhenCreated       string   `json:"when_created"`
	WhenChanged       string   `json:"when_changed"`
	LastLogonTS       string   `json:"last_logon_timestamp"`
}

type ComputerInfo struct {
	DN                 string `json:"dn"`
	CN                 string `json:"cn"`
	Name               string `json:"name"`
	DNSHostName        string `json:"dns_host_name"`
	OperatingSystem    string `json:"operating_system"`
	OperatingSystemVer string `json:"operating_system_version"`
	LastLogonTS        string `json:"last_logon_timestamp"`
	ResolvedIP         string `json:"resolved_ip"`
}

type MatchResult struct {
	User     string        `json:"user"`
	Host     string        `json:"host"`
	IP       string        `json:"ip"`
	UserInfo *UserInfo     `json:"user_info,omitempty"`
	Computer *ComputerInfo `json:"computer,omitempty"`
}

func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("ldap url is required")
	}
	if cfg.BindDN == "" {
		return nil, fmt.Errorf("ldap bind dn is required")
	}
	if cfg.BindPassword == "" {
		return nil, fmt.Errorf("ldap bind password is required")
	}
	if cfg.BaseDN == "" {
		return nil, fmt.Errorf("ldap base dn is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}

	return &Client{cfg: cfg}, nil
}

func (c *Client) UserBySAMAccountName(username string) (*UserInfo, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username is empty")
	}

	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	baseDN := c.cfg.UserBaseDN
	if baseDN == "" {
		baseDN = c.cfg.BaseDN
	}

	filter := fmt.Sprintf("(&(objectClass=user)(objectCategory=person)(sAMAccountName=%s))", ldap.EscapeFilter(username))
	attrs := []string{
		"distinguishedName",
		"cn",
		"displayName",
		"sAMAccountName",
		"userPrincipalName",
		"mail",
		"department",
		"company",
		"title",
		"telephoneNumber",
		"mobile",
		"description",
		"memberOf",
		"whenCreated",
		"whenChanged",
		"lastLogonTimestamp",
	}

	entry, err := c.searchOne(conn, baseDN, filter, attrs)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	return &UserInfo{
		DN:                valueOrUnknown(entry.GetAttributeValue("distinguishedName")),
		CN:                valueOrUnknown(entry.GetAttributeValue("cn")),
		DisplayName:       valueOrUnknown(entry.GetAttributeValue("displayName")),
		SAMAccountName:    valueOrUnknown(entry.GetAttributeValue("sAMAccountName")),
		UserPrincipalName: valueOrUnknown(entry.GetAttributeValue("userPrincipalName")),
		Mail:              valueOrUnknown(entry.GetAttributeValue("mail")),
		Department:        valueOrUnknown(entry.GetAttributeValue("department")),
		Company:           valueOrUnknown(entry.GetAttributeValue("company")),
		Title:             valueOrUnknown(entry.GetAttributeValue("title")),
		TelephoneNumber:   valueOrUnknown(entry.GetAttributeValue("telephoneNumber")),
		Mobile:            valueOrUnknown(entry.GetAttributeValue("mobile")),
		Description:       valueOrUnknown(entry.GetAttributeValue("description")),
		MemberOf:          valuesOrUnknown(entry.GetAttributeValues("memberOf")),
		WhenCreated:       valueOrUnknown(entry.GetAttributeValue("whenCreated")),
		WhenChanged:       valueOrUnknown(entry.GetAttributeValue("whenChanged")),
		LastLogonTS:       valueOrUnknown(entry.GetAttributeValue("lastLogonTimestamp")),
	}, nil
}

func (c *Client) ComputerByHost(host string) (*ComputerInfo, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("host is empty")
	}

	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	baseDN := c.cfg.ComputerBaseDN
	if baseDN == "" {
		baseDN = c.cfg.BaseDN
	}

	filter := fmt.Sprintf("(&(objectClass=computer)(|(cn=%s)(name=%s)(dNSHostName=%s)))",
		ldap.EscapeFilter(host),
		ldap.EscapeFilter(host),
		ldap.EscapeFilter(host),
	)
	attrs := []string{
		"distinguishedName",
		"cn",
		"name",
		"dNSHostName",
		"operatingSystem",
		"operatingSystemVersion",
		"lastLogonTimestamp",
	}

	entry, err := c.searchOne(conn, baseDN, filter, attrs)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	dnsHostName := valueOrUnknown(entry.GetAttributeValue("dNSHostName"))
	resolvedIP := UnknownValue
	if dnsHostName != UnknownValue {
		if ip, err := c.LookupIP(dnsHostName); err == nil {
			resolvedIP = ip
		}
	}

	return &ComputerInfo{
		DN:                 valueOrUnknown(entry.GetAttributeValue("distinguishedName")),
		CN:                 valueOrUnknown(entry.GetAttributeValue("cn")),
		Name:               valueOrUnknown(entry.GetAttributeValue("name")),
		DNSHostName:        dnsHostName,
		OperatingSystem:    valueOrUnknown(entry.GetAttributeValue("operatingSystem")),
		OperatingSystemVer: valueOrUnknown(entry.GetAttributeValue("operatingSystemVersion")),
		LastLogonTS:        valueOrUnknown(entry.GetAttributeValue("lastLogonTimestamp")),
		ResolvedIP:         resolvedIP,
	}, nil
}

func (c *Client) Match(username, host string) (*MatchResult, error) {
	result := &MatchResult{
		User: UnknownValue,
		Host: UnknownValue,
		IP:   UnknownValue,
	}

	if username != "" {
		userInfo, err := c.UserBySAMAccountName(username)
		if err != nil {
			return nil, err
		}
		if userInfo != nil {
			result.UserInfo = userInfo
			result.User = userInfo.SAMAccountName
		}
	}

	if host != "" {
		computer, err := c.ComputerByHost(host)
		if err != nil {
			return nil, err
		}
		if computer != nil {
			result.Computer = computer
			result.Host = firstKnown(computer.DNSHostName, computer.Name, computer.CN)
			result.IP = computer.ResolvedIP
		}
	}

	return result, nil
}

func (c *Client) LookupIP(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("host is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
	defer cancel()

	resolver := net.Resolver{}
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipv4 := addr.IP.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0].IP.String(), nil
	}
	return "", fmt.Errorf("no ip address found for %s", host)
}

func (c *Client) connect() (*ldap.Conn, error) {
	dialOpts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: c.cfg.Timeout})}
	if strings.HasPrefix(strings.ToLower(c.cfg.URL), "ldaps://") {
		dialOpts = append(dialOpts, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: c.cfg.Insecure}))
	}

	conn, err := ldap.DialURL(c.cfg.URL, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("ldap dial failed: %w", err)
	}

	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ldap bind failed: %w", err)
	}

	return conn, nil
}

func (c *Client) searchOne(conn *ldap.Conn, baseDN, filter string, attrs []string) (*ldap.Entry, error) {
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		int(c.cfg.Timeout.Seconds()),
		false,
		filter,
		attrs,
		nil,
	)

	resp, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap search failed: %w", err)
	}
	if len(resp.Entries) == 0 {
		return nil, nil
	}
	return resp.Entries[0], nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	return host
}

func firstKnown(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" && v != UnknownValue {
			return v
		}
	}
	return UnknownValue
}

func valueOrUnknown(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return UnknownValue
	}
	return v
}

func valuesOrUnknown(vs []string) []string {
	if len(vs) == 0 {
		return []string{UnknownValue}
	}
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return []string{UnknownValue}
	}
	return out
}
