package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"

	"github.com/google/go-github/v79/github"
	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

var githubClient *github.Client

func init() {
	accessToken, loaded := os.LookupEnv("ACCESS_TOKEN")
	if !loaded {
		githubClient = github.NewClient(nil)
		return
	}
	transport := &github.BasicAuthTransport{
		Username: accessToken,
	}
	githubClient = github.NewClient(transport.Client())
}

func fetch(from string) (*github.RepositoryRelease, error) {
	names := strings.SplitN(from, "/", 2)
	latestRelease, _, err := githubClient.Repositories.GetLatestRelease(context.Background(), names[0], names[1])
	if err != nil {
		return nil, err
	}
	return latestRelease, err
}

func get(downloadURL *string) ([]byte, error) {
	log.Info("download ", *downloadURL)
	response, err := http.Get(*downloadURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

func download(release *github.RepositoryRelease) ([]byte, error) {
	geositeAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "geosite.dat"
	})
	geositeChecksumAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "geosite.dat.sha256sum"
	})
	if geositeAsset == nil {
		if release.Name == nil {
			return nil, E.New("Geosite asset name not found")
		}
		return nil, E.New("Geosite asset not found in upstream release ", release.Name)
	}
	if geositeChecksumAsset == nil {
		return nil, E.New("Geosite asset not found in upstream release ", release.Name)
	}
	data, err := get(geositeAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	remoteChecksum, err := get(geositeChecksumAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	checksum := sha256.Sum256(data)
	if hex.EncodeToString(checksum[:]) != string(remoteChecksum[:64]) {
		return nil, E.New("Checksum mismatch")
	}
	return data, nil
}

func parse(vGeositeData []byte) (map[string][]geosite.Item, error) {
	vGeositeList := routercommon.GeoSiteList{}
	err := proto.Unmarshal(vGeositeData, &vGeositeList)
	if err != nil {
		return nil, err
	}
	domainMap := make(map[string][]geosite.Item)
	for _, vGeositeEntry := range vGeositeList.Entry {
		code := strings.ToLower(vGeositeEntry.CountryCode)
		domains := make([]geosite.Item, 0, len(vGeositeEntry.Domain)*2)
		attributes := make(map[string][]*routercommon.Domain)
		for _, domain := range vGeositeEntry.Domain {
			if len(domain.Attribute) > 0 {
				for _, attribute := range domain.Attribute {
					attributes[attribute.Key] = append(attributes[attribute.Key], domain)
				}
			}
			switch domain.Type {
			case routercommon.Domain_Plain:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainKeyword,
					Value: domain.Value,
				})
			case routercommon.Domain_Regex:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainRegex,
					Value: domain.Value,
				})
			case routercommon.Domain_RootDomain:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainSuffix,
					Value: domain.Value,
				})
			case routercommon.Domain_Full:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomain,
					Value: domain.Value,
				})
			}
		}
		domainMap[code] = common.Uniq(domains)
		for attribute, attributeEntries := range attributes {
			attributeDomains := make([]geosite.Item, 0, len(attributeEntries)*2)
			for _, domain := range attributeEntries {
				switch domain.Type {
				case routercommon.Domain_Plain:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainKeyword,
						Value: domain.Value,
					})
				case routercommon.Domain_Regex:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainRegex,
						Value: domain.Value,
					})
				case routercommon.Domain_RootDomain:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainSuffix,
						Value: domain.Value,
					})
				case routercommon.Domain_Full:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomain,
						Value: domain.Value,
					})
				}
			}
			domainMap[code+"@"+attribute] = common.Uniq(attributeDomains)
		}
	}
	return domainMap, nil
}

type filterCodePair struct {
	code    string
	badCode string
}

func filterTags(data map[string][]geosite.Item) {
	var codeList []string
	for code := range data {
		codeList = append(codeList, code)
	}
	var badCodeList []filterCodePair
	var deletedCodeMap []string
	var filteredCodeMap []string
	for _, code := range codeList {
		codeParts := strings.Split(code, "@")
		if len(codeParts) != 2 {
			continue
		}
		leftParts := strings.Split(codeParts[0], "-")
		var lastName string
		if len(leftParts) > 1 {
			lastName = leftParts[len(leftParts)-1]
		}
		if lastName == "" {
			lastName = codeParts[0]
		}
		if lastName == codeParts[1] {
			delete(data, code)
			deletedCodeMap = append(deletedCodeMap, code)
			continue
		}
		if "!"+lastName == codeParts[1] {
			badCodeList = append(badCodeList, filterCodePair{
				code:    codeParts[0],
				badCode: code,
			})
		} else if lastName == "!"+codeParts[1] {
			badCodeList = append(badCodeList, filterCodePair{
				code:    codeParts[0],
				badCode: code,
			})
		}
	}
	for _, it := range badCodeList {
		badList := data[it.badCode]
		if badList == nil {
			panic("Bad list not found: " + it.badCode)
		}
		delete(data, it.badCode)
		newMap := make(map[geosite.Item]bool)
		for _, item := range data[it.code] {
			newMap[item] = true
		}
		for _, item := range badList {
			delete(newMap, item)
		}
		newList := make([]geosite.Item, 0, len(newMap))
		for item := range newMap {
			newList = append(newList, item)
		}
		data[it.code] = newList
		filteredCodeMap = append(filteredCodeMap, it.badCode)
	}
	slices.Sort(deletedCodeMap)
	slices.Sort(filteredCodeMap)
	log.Info("Deleted: " + strings.Join(deletedCodeMap, ", "))
	log.Info("Filtered: " + strings.Join(filteredCodeMap, ",") + "\n")
}

func mergeTags(data map[string][]geosite.Item) {
	var codeList []string
	for code := range data {
		codeList = append(codeList, code)
	}
	var cnCodeList []string
	for _, code := range codeList {
		codeParts := strings.Split(code, "@")
		if len(codeParts) != 2 {
			continue
		}
		if codeParts[1] != "cn" {
			continue
		}
		if !strings.HasPrefix(codeParts[0], "category-") {
			continue
		}
		if strings.HasSuffix(codeParts[0], "-cn") || strings.HasSuffix(codeParts[0], "-!cn") {
			continue
		}
		cnCodeList = append(cnCodeList, code)
	}
	for _, code := range codeList {
		if !strings.HasPrefix(code, "category-") {
			continue
		}
		if !strings.HasSuffix(code, "-cn") {
			continue
		}
		if strings.Contains(code, "@") {
			continue
		}
		cnCodeList = append(cnCodeList, code)
	}
	newMap := make(map[geosite.Item]bool)
	for _, item := range data["cn"] {
		newMap[item] = true
	}
	for _, code := range cnCodeList {
		for _, item := range data[code] {
			newMap[item] = true
		}
	}
	newList := make([]geosite.Item, 0, len(newMap))
	for item := range newMap {
		newList = append(newList, item)
	}
	data["custom-cn"] = newList
	log.Info("Merged cn categories: " + strings.Join(cnCodeList, ", "))
}

func writeRuleSet(ruleSetPath string, ruleSet option.PlainRuleSet) error {
	srsPath, _ := filepath.Abs(ruleSetPath + ".srs")
	outputRuleSet, err := os.Create(srsPath)
	if err != nil {
		E.New("Failed to create ", srsPath)
		return err
	}
	err = srs.Write(outputRuleSet, ruleSet, C.RuleSetVersionCurrent)
	outputRuleSet.Close()
	if err != nil {
		E.New("Failed to write ", srsPath)
		return err
	}
	// log.Trace("Wrote ", srsPath)
	jsonPath, _ := filepath.Abs(ruleSetPath + ".json")
	outputRuleSetSource, err := os.Create(jsonPath)
	if err != nil {
		return E.New("Failed to create ", jsonPath)
	}
	var ruleSetSource option.PlainRuleSetCompat
	ruleSetSource.Version = C.RuleSetVersionCurrent
	ruleSetSource.Options = ruleSet
	encoder := json.NewEncoder(outputRuleSetSource)
	encoder.SetIndent("", "	")
	err = encoder.Encode(ruleSetSource)
	outputRuleSetSource.Close()
	if err != nil {
		return E.New("Failed to create ", jsonPath)
	}
	// log.Trace("Wrote ", jsonPath)
	return nil
}

func filterCommon(a []string, b []string) ([]string, []string) {
	newMap := make(map[string]uint8, len(a)+len(b))
	// mark with two bits
	for _, key := range a {
		newMap[key] |= (1 << 0)
	}
	for _, key := range b {
		newMap[key] |= (1 << 1)
	}
	inA := make([]string, 0, len(a))
	inB := make([]string, 0, len(b))
	for key, value := range newMap {
		switch value {
		case 1:
			inA = append(inA, key)
		case 2:
			inB = append(inB, key)
		}
	}
	return inA, inB
}

type logicalRulePair struct {
	Code string
	Rule option.DefaultRule
}

func generateLogical(ruleSetOutput string, include logicalRulePair, exclude logicalRulePair) error {
	var (
		includeHeadlessRule option.DefaultHeadlessRule
		excludeHeadlessRule option.DefaultHeadlessRule
		dirtyIncludeDomain  []string
	)
	excludeHeadlessRule.Invert = true
	dirtyIncludeDomain, excludeHeadlessRule.Domain = filterCommon(
		include.Rule.Domain, exclude.Rule.Domain,
	)
	includeHeadlessRule.DomainSuffix, excludeHeadlessRule.DomainSuffix = filterCommon(
		include.Rule.DomainSuffix, exclude.Rule.DomainSuffix,
	)
	includeHeadlessRule.DomainKeyword, excludeHeadlessRule.DomainKeyword = filterCommon(
		include.Rule.DomainKeyword, exclude.Rule.DomainKeyword,
	)
	includeHeadlessRule.DomainRegex, excludeHeadlessRule.DomainRegex = filterCommon(
		include.Rule.DomainRegex, exclude.Rule.DomainRegex,
	)
	includeHeadlessRule.Domain, _ = filterCommon(dirtyIncludeDomain, exclude.Rule.DomainSuffix)

	var logicalRuleSet option.PlainRuleSet
	logicalRuleSet.Rules = []option.HeadlessRule{
		{
			Type: C.RuleTypeLogical,
			LogicalOptions: option.LogicalHeadlessRule{
				Mode: "and",
				Rules: []option.HeadlessRule{
					{
						Type:           C.RuleTypeDefault,
						DefaultOptions: excludeHeadlessRule,
					},
					{
						Type:           C.RuleTypeDefault,
						DefaultOptions: includeHeadlessRule,
					},
				},
			},
		},
	}
	ruleSetPath, _ := filepath.Abs(filepath.Join(ruleSetOutput, "logical-"+include.Code+"-and-not-"+exclude.Code))
	err := writeRuleSet(ruleSetPath, logicalRuleSet)
	if err != nil {
		return err
	}
	var includeRuleSet option.PlainRuleSet
	includeRuleSet.Rules = []option.HeadlessRule{
		{
			Type:           C.RuleTypeDefault,
			DefaultOptions: includeHeadlessRule,
		},
	}
	ruleSetPath, _ = filepath.Abs(filepath.Join(ruleSetOutput, "logical-include-"+include.Code))
	err = writeRuleSet(ruleSetPath, includeRuleSet)
	if err != nil {
		return err
	}
	var excludeRuleSet option.PlainRuleSet
	excludeRuleSet.Rules = []option.HeadlessRule{
		{
			Type:           C.RuleTypeDefault,
			DefaultOptions: excludeHeadlessRule,
		},
	}
	ruleSetPath, _ = filepath.Abs(filepath.Join(ruleSetOutput, "logical-exclude-"+exclude.Code))
	err = writeRuleSet(ruleSetPath, excludeRuleSet)
	if err != nil {
		return err
	}
	return nil
}

func generate(release *github.RepositoryRelease, ruleSetOutput string) error {
	vData, err := download(release)
	if err != nil {
		return err
	}
	domainMap, err := parse(vData)
	if err != nil {
		return err
	}
	filterTags(domainMap)
	mergeTags(domainMap)
	os.RemoveAll(ruleSetOutput)
	err = os.MkdirAll(ruleSetOutput, 0o755)
	if err != nil {
		return err
	}
	var (
		logicalInclude logicalRulePair
		logicalExclude logicalRulePair
	)
	for code, domains := range domainMap {
		var headlessRule option.DefaultHeadlessRule
		defaultRule := geosite.Compile(domains)
		slices.Sort(defaultRule.Domain)
		slices.Sort(defaultRule.DomainSuffix)
		slices.Sort(defaultRule.DomainKeyword)
		slices.Sort(defaultRule.DomainRegex)
		headlessRule.Domain = defaultRule.Domain
		headlessRule.DomainSuffix = defaultRule.DomainSuffix
		headlessRule.DomainKeyword = defaultRule.DomainKeyword
		headlessRule.DomainRegex = defaultRule.DomainRegex
		var plainRuleSet option.PlainRuleSet
		plainRuleSet.Rules = []option.HeadlessRule{
			{
				Type:           C.RuleTypeDefault,
				DefaultOptions: headlessRule,
			},
		}
		ruleSetPath, _ := filepath.Abs(filepath.Join(ruleSetOutput, code))
		err = writeRuleSet(ruleSetPath, plainRuleSet)
		if err != nil {
			return err
		}
		if code == "custom-cn" {
			logicalInclude.Code = code
			logicalInclude.Rule = defaultRule
		}
		if code == "geolocation-!cn" {
			logicalExclude.Code = code
			logicalExclude.Rule = defaultRule
		}
	}
	log.Info("Wrote Geosite rule-sets.")
	if logicalInclude.Rule.DomainSuffix == nil || logicalExclude.Rule.DomainSuffix == nil {
		return E.New("Logical Rule Source Error")
	}
	err = generateLogical(ruleSetOutput, logicalInclude, logicalExclude)
	if err != nil {
		return err
	}
	log.Info("Wrote Logical rule-set.")
	return nil
}

func setActionOutput(name string, content string) {
	outputFile := os.Getenv("GITHUB_OUTPUT")
	output, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		E.New(err)
		return
	}
	defer output.Close()

	_, err = output.WriteString(name + "=" + content + "\n")
	if err != nil {
		E.New(err)
		return
	}
}

func release(source string, destination string, ruleSetOutput string) error {
	sourceRelease, err := fetch(source)
	if err != nil {
		return err
	}
	destinationRelease, err := fetch(destination)
	if err != nil {
		log.Warn("Destination repo does not exist.")
	} else {
		if os.Getenv("NO_SKIP") != "true" && strings.Contains(*destinationRelease.TagName, *sourceRelease.TagName) {
			log.Warn("Current release is already the latest version.")
			setActionOutput("skip", "true")
			return nil
		}
	}
	err = generate(sourceRelease, ruleSetOutput)
	if err != nil {
		return err
	}
	setActionOutput("tag", *sourceRelease.TagName)
	return nil
}

func main() {
	err := release(
		"Loyalsoldier/v2ray-rules-dat",
		"waiting-parachute/sing-geosite",
		"rule-set",
	)
	if err != nil {
		log.Fatal(err)
	}
}
