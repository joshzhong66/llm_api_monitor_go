package parser

import (
	"path/filepath"
	"strings"

	"llm_api_monitor/internal/model"
)

// TargetMatcher matches domains/IPs to vendor names.
type TargetMatcher struct {
	exactMap      map[string]string     // lowercase domain -> vendor
	wildcardRules []wildcardRule
}

type wildcardRule struct {
	pattern string
	vendor  string
}

// NewTargetMatcher creates a matcher from target rules.
func NewTargetMatcher(rules []model.TargetRule) *TargetMatcher {
	tm := &TargetMatcher{
		exactMap: make(map[string]string),
	}
	for _, r := range rules {
		pattern := strings.ToLower(r.DomainPattern)
		if r.MatchType == "wildcard" || strings.Contains(pattern, "*") {
			tm.wildcardRules = append(tm.wildcardRules, wildcardRule{
				pattern: pattern,
				vendor:  r.Vendor,
			})
		} else {
			tm.exactMap[pattern] = r.Vendor
		}
	}
	return tm
}

// Match returns the vendor for a given domain token, or "" if no match.
func (tm *TargetMatcher) Match(token string) string {
	token = strings.ToLower(token)
	if v, ok := tm.exactMap[token]; ok {
		return v
	}
	for _, wr := range tm.wildcardRules {
		if matched, _ := filepath.Match(wr.pattern, token); matched {
			return wr.vendor
		}
	}
	return ""
}

// DefaultTargetRules returns the built-in target rules.
func DefaultTargetRules() []model.TargetRule {
	now := model.NowLocalText()
	rules := []struct {
		vendor, domain, matchType, source string
	}{
		{"ChatGPT / OpenAI", "api.openai.com", "exact", "official"},
		{"ChatGPT / OpenAI", "chat.openai.com", "exact", "official"},
		{"ChatGPT / OpenAI", "chatgpt.com", "exact", "official"},
		{"Azure OpenAI", "*.openai.azure.com", "wildcard", "official"},
		{"Claude / Anthropic", "api.anthropic.com", "exact", "official"},
		{"Claude / Anthropic", "claude.ai", "exact", "official"},
		{"Gemini / Google AI", "generativelanguage.googleapis.com", "exact", "official"},
		{"Gemini / Google AI", "aiplatform.googleapis.com", "exact", "official"},
		{"Gemini / Google AI", "aistudio.google.com", "exact", "official"},
		{"Gemini / Google AI", "gemini.google.com", "exact", "official"},
		{"Kimi / Moonshot", "api.moonshot.cn", "exact", "official"},
		{"Kimi / Moonshot", "api.moonshot.ai", "exact", "official"},
		{"Kimi / Moonshot", "kimi.com", "exact", "official"},
		{"Kimi / Moonshot", "kimi.moonshot.cn", "exact", "official"},
		{"Kimi / Moonshot", "platform.kimi.ai", "exact", "official"},
		{"Kimi / Moonshot", "platform.moonshot.ai", "exact", "official"},
		{"\u767e\u5ea6 / \u5343\u5e06", "qianfan.baidubce.com", "exact", "official"},
		{"\u817e\u8baf / \u6df7\u5143", "hunyuan.tencentcloudapi.com", "exact", "official"},
		{"\u817e\u8baf / \u6df7\u5143", "hunyuan.*.tencentcloudapi.com", "wildcard", "official"},
		{"\u817e\u8baf / \u6df7\u5143", "api.hunyuan.cloud.tencent.com", "exact", "official"},
		{"\u817e\u8baf / \u6df7\u5143", "hunyuan.ai.intl.tencentcloudapi.com", "exact", "official"},
		{"\u5343\u95ee / \u901a\u4e49", "dashscope.aliyuncs.com", "exact", "official"},
		{"\u5343\u95ee / \u901a\u4e49", "dashscope-intl.aliyuncs.com", "exact", "official"},
		{"\u5343\u95ee / \u901a\u4e49", "dashscope-us.aliyuncs.com", "exact", "official"},
		{"\u5343\u95ee / \u901a\u4e49", "cn-hongkong.dashscope.aliyuncs.com", "exact", "official"},
		{"\u5343\u95ee / \u901a\u4e49", "qwen.ai", "exact", "official"},
		{"\u5343\u95ee / \u901a\u4e49", "tongyi.aliyun.com", "exact", "official"},
		{"\u8c46\u5305 / \u706b\u5c71\u5f15\u64ce", "ark.cn-beijing.volces.com", "exact", "official"},
		{"\u8c46\u5305 / \u706b\u5c71\u5f15\u64ce", "ark.ap-southeast.bytepluses.com", "exact", "official"},
		{"\u8c46\u5305 / \u706b\u5c71\u5f15\u64ce", "ark.eu-west.bytepluses.com", "exact", "official"},
		{"MiniMax", "api.minimax.io", "exact", "official"},
		{"MiniMax", "api.minimaxi.com", "exact", "official"},
		{"\u667a\u8c31", "open.bigmodel.cn", "exact", "official"},
		{"DeepSeek", "api.deepseek.com", "exact", "official"},
		{"DeepSeek", "platform.deepseek.com", "exact", "official"},
		{"LLM API Proxy", "llm-api-proxy.hnfunny.com", "exact", "custom"},
		{"Mistral", "api.mistral.ai", "exact", "official"},
		{"Mistral", "console.mistral.ai", "exact", "official"},
		{"Cohere", "api.cohere.com", "exact", "official"},
		{"Grok / xAI", "api.x.ai", "exact", "official"},
		{"Grok / xAI", "accounts.x.ai", "exact", "official"},
		{"Grok / xAI", "grok.com", "exact", "official"},
		{"Amazon Bedrock", "bedrock-runtime.*.amazonaws.com", "wildcard", "official"},
		{"Amazon Bedrock", "bedrock.*.amazonaws.com", "wildcard", "official"},
		{"Amazon Bedrock", "bedrock-mantle.*.api.aws", "wildcard", "official"},
	}

	var result []model.TargetRule
	for _, r := range rules {
		result = append(result, model.TargetRule{
			Vendor:        r.vendor,
			DomainPattern: r.domain,
			MatchType:     r.matchType,
			Source:        r.source,
			Enabled:       1,
			CreatedAt:     now,
			UpdatedAt:     now,
		})
	}
	return result
}
