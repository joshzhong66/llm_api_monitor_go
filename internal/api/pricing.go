package api

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
)

// PricingRule represents a row from the pricing XLSX.
type PricingRule struct {
	ChannelType string
	Vendor      string
	Model       string
	InputPer1M  float64
	OutputPer1M float64
	SourceURL   string
}

// PricingCatalog holds all pricing rules loaded from XLSX.
type PricingCatalog struct {
	mu    sync.Once
	rules []PricingRule
	cache map[string]*PricingRule // "vendor|domain" -> rule
}

// DefaultPricingSelections maps monitor vendor names to XLSX lookup keys.
var DefaultPricingSelections = map[string]struct {
	ChannelType, Vendor, Model string
}{
	"ChatGPT / OpenAI":  {"Azure OpenAI", "OpenAI", "gpt-5.4"},
	"Azure OpenAI":      {"Azure OpenAI", "OpenAI", "gpt-5.4"},
	"Claude / Anthropic": {"AWS Claude", "Anthropic", "claude-sonnet-4-6"},
	"Gemini / Google AI": {"Vertex AI", "Google Cloud", "gemini-3-flash-preview"},
	"MiniMax":            {"MiniMax", "MiniMax", "MiniMax-M2.5"},
	"\u667a\u8c31":       {"\u667a\u8c31 GLM-4V", "BigModel", "glm-5"},
	"\u5343\u95ee / \u901a\u4e49": {"\u963f\u91cc\u4e91\u767e\u70bc", "Alibaba", "qwen3.5-flash"},
}

var globalCatalog PricingCatalog

// LoadPricingCatalog loads pricing rules from the XLSX file.
func LoadPricingCatalog(xlsxPath string) {
	globalCatalog.mu.Do(func() {
		globalCatalog.cache = make(map[string]*PricingRule)
		rules, err := parsePricingXLSX(xlsxPath)
		if err != nil {
			return
		}
		globalCatalog.rules = rules
	})
}

// SelectPricingRule finds the best pricing rule for a vendor+domain.
func SelectPricingRule(vendor, domain string) *PricingRule {
	cacheKey := fmt.Sprintf("%s|%s", vendor, strings.ToLower(domain))
	if r, ok := globalCatalog.cache[cacheKey]; ok {
		return r
	}

	sel, ok := DefaultPricingSelections[vendor]
	if !ok {
		globalCatalog.cache[cacheKey] = nil
		return nil
	}

	var candidates []PricingRule
	for _, r := range globalCatalog.rules {
		if r.ChannelType != sel.ChannelType || r.Vendor != sel.Vendor || r.Model != sel.Model {
			continue
		}
		candidates = append(candidates, r)
	}
	if len(candidates) == 0 {
		globalCatalog.cache[cacheKey] = nil
		return nil
	}

	// Pick the one with lowest input cost
	best := &candidates[0]
	for i := 1; i < len(candidates); i++ {
		if candidates[i].InputPer1M < best.InputPer1M {
			best = &candidates[i]
		}
	}
	result := *best // copy
	globalCatalog.cache[cacheKey] = &result
	return &result
}

// parsePricingXLSX reads the pricing XLSX (simple xml-based parser, no external dep).
func parsePricingXLSX(path string) ([]PricingRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, _ := f.Stat()
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return nil, err
	}

	// Read shared strings
	shared := readSharedStrings(zr)

	// Read sheet1
	var sheetFile io.ReadCloser
	for _, zf := range zr.File {
		if zf.Name == "xl/worksheets/sheet1.xml" {
			sheetFile, err = zf.Open()
			if err != nil {
				return nil, err
			}
			break
		}
	}
	if sheetFile == nil {
		return nil, fmt.Errorf("sheet1.xml not found")
	}
	defer sheetFile.Close()

	rows := parseSheet(sheetFile, shared)
	if len(rows) < 2 {
		return nil, fmt.Errorf("no data rows")
	}

	header := rows[0]
	var rules []PricingRule
	for _, row := range rows[1:] {
		item := make(map[string]string)
		for i, key := range header {
			if i < len(row) {
				item[key] = row[i]
			}
		}
		rules = append(rules, PricingRule{
			ChannelType: item["channel_type"],
			Vendor:      item["vendor"],
			Model:       item["model"],
			InputPer1M:  parseFloat(item["input_per_1m"]),
			OutputPer1M: parseFloat(item["output_per_1m"]),
			SourceURL:   item["source_url"],
		})
	}
	return rules, nil
}

func readSharedStrings(zr *zip.Reader) []string {
	for _, zf := range zr.File {
		if zf.Name == "xl/sharedStrings.xml" {
			rc, err := zf.Open()
			if err != nil {
				return nil
			}
			defer rc.Close()
			return parseSharedStrings(rc)
		}
	}
	return nil
}

func parseSharedStrings(r io.Reader) []string {
	decoder := xml.NewDecoder(r)
	var shared []string
	var inSI, inT bool
	var current strings.Builder

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "si" {
				inSI = true
				current.Reset()
			} else if t.Name.Local == "t" && inSI {
				inT = true
			}
		case xml.CharData:
			if inT {
				current.Write(t)
			}
		case xml.EndElement:
			if t.Name.Local == "t" {
				inT = false
			} else if t.Name.Local == "si" {
				shared = append(shared, current.String())
				inSI = false
			}
		}
	}
	return shared
}

func parseSheet(r io.Reader, shared []string) [][]string {
	decoder := xml.NewDecoder(r)
	var rows [][]string
	var currentRow []string
	var cellRef, cellType string
	var inV bool
	var vText strings.Builder

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "row" {
				currentRow = nil
			} else if t.Name.Local == "c" {
				cellRef = ""
				cellType = ""
				for _, a := range t.Attr {
					if a.Name.Local == "r" {
						cellRef = a.Value
					} else if a.Name.Local == "t" {
						cellType = a.Value
					}
				}
				// Pad row to match column index
				colIdx := excelColIndex(cellRef)
				for len(currentRow) <= colIdx {
					currentRow = append(currentRow, "")
				}
			} else if t.Name.Local == "v" {
				inV = true
				vText.Reset()
			}
		case xml.CharData:
			if inV {
				vText.Write(t)
			}
		case xml.EndElement:
			if t.Name.Local == "v" {
				inV = false
				val := vText.String()
				if cellType == "s" && val != "" {
					idx, err := strconv.Atoi(val)
					if err == nil && idx < len(shared) {
						val = shared[idx]
					}
				}
				colIdx := excelColIndex(cellRef)
				if colIdx < len(currentRow) {
					currentRow[colIdx] = val
				}
			} else if t.Name.Local == "row" {
				if len(currentRow) > 0 {
					rows = append(rows, currentRow)
				}
			}
		}
	}
	return rows
}

func excelColIndex(ref string) int {
	col := 0
	for _, c := range ref {
		if c >= 'A' && c <= 'Z' {
			col = col*26 + int(c-'A') + 1
		} else {
			break
		}
	}
	if col > 0 {
		col--
	}
	return col
}

func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}
