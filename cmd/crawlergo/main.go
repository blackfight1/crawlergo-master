package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Qianlitp/crawlergo/pkg"
	"github.com/Qianlitp/crawlergo/pkg/config"
	"github.com/Qianlitp/crawlergo/pkg/logger"
	model2 "github.com/Qianlitp/crawlergo/pkg/model"
	"github.com/Qianlitp/crawlergo/pkg/tools"
	"github.com/Qianlitp/crawlergo/pkg/tools/requests"
	"github.com/panjf2000/ants/v2"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

type Result struct {
	ReqList       []Request `json:"req_list"`
	AllReqList    []Request `json:"all_req_list"`
	AllDomainList []string  `json:"all_domain_list"`
	SubDomainList []string  `json:"sub_domain_list"`
}

type Request struct {
	Url     string                 `json:"url"`
	Method  string                 `json:"method"`
	Headers map[string]interface{} `json:"headers"`
	Data    string                 `json:"data"`
	Source  string                 `json:"source"`
}

type ProxyTask struct {
	req       *model2.Request
	pushProxy string
}

const (
	DefaultMaxPushProxyPoolMax = 10
	DefaultLogLevel            = "Info"
)

var (
	taskConfig              pkg.TaskConfig
	outputMode              string
	postData                string
	signalChan              chan os.Signal
	ignoreKeywords          = cli.NewStringSlice(config.DefaultIgnoreKeywords...)
	customFormTypeValues    = cli.NewStringSlice()
	customFormKeywordValues = cli.NewStringSlice()
	pushAddress             string
	pushProxyPoolMax        int
	pushProxyWG             sync.WaitGroup
	outputJsonPath          string
	outputTxtPath           string
	inputFilePath           string
	logLevel                string
	Version                 string
)

func main() {
	author := cli.Author{
		Name:  "9ian1i",
		Email: "9ian1itp@gmail.com",
	}

	app := &cli.App{
		Name:      "crawlergo",
		Usage:     "A powerful browser crawler for web vulnerability scanners",
		UsageText: "crawlergo [global options] url1 url2 url3 ... (must be same host)",
		Version:   Version,
		Authors:   []*cli.Author{&author},
		Flags:     cliFlags,
		Action:    run,
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.Logger.Fatal(err)
	}
}

func run(c *cli.Context) error {
	signalChan = make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT)

	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logger.Logger.Fatal(err)
	}
	logger.Logger.SetLevel(level)

	rawTargets, err := collectRawTargets(c)
	if err != nil {
		return err
	}
	targets := buildTargets(rawTargets)
	if len(targets) == 0 {
		logger.Logger.Fatal("no validate target.")
	}

	taskConfig.IgnoreKeywords = ignoreKeywords.Value()
	if taskConfig.Proxy != "" {
		logger.Logger.Info("request with proxy: ", taskConfig.Proxy)
	}

	taskConfig.CustomFormValues, err = parseCustomFormValues(customFormTypeValues.Value())
	if err != nil {
		logger.Logger.Fatal(err)
	}
	taskConfig.CustomFormKeywordValues, err = keywordStringToMap(customFormKeywordValues.Value())
	if err != nil {
		logger.Logger.Fatal(err)
	}

	if len(taskConfig.CustomFormValues) > 0 {
		logger.Logger.Info("Custom form values, " + tools.MapStringFormat(taskConfig.CustomFormValues))
	}
	if len(taskConfig.CustomFormKeywordValues) > 0 {
		logger.Logger.Info("Custom form keyword values, " + tools.MapStringFormat(taskConfig.CustomFormKeywordValues))
	}
	if _, ok := taskConfig.CustomFormValues["default"]; !ok {
		logger.Logger.Info("If no matches, default form input text: " + config.DefaultInputText)
		taskConfig.CustomFormValues["default"] = config.DefaultInputText
	}

	isBatchMode := inputFilePath != ""
	start := time.Now()
	var result *pkg.Result

	if isBatchMode {
		result = runBatchTasks(targets)
	} else {
		task, err := pkg.NewCrawlerTask(targets, taskConfig)
		if err != nil {
			logger.Logger.Error("create crawler task failed.")
			os.Exit(-1)
		}
		if len(targets) != 0 {
			logger.Logger.Infof("Init crawler task, host: %s, max tab count: %d, max crawl count: %d, max runtime: %ds",
				targets[0].URL.Host, taskConfig.MaxTabsCount, taskConfig.MaxCrawlCount, taskConfig.MaxRunTime)
			logger.Logger.Info("filter mode: ", taskConfig.FilterMode)
		}
		go handleExit(task)
		logger.Logger.Info("Start crawling.")
		task.Run()
		result = task.Result
	}

	logger.Logger.Infof("Task finished, %d results, %d requests, %d subdomains, %d domains found, runtime: %d",
		len(result.ReqList), len(result.AllReqList), len(result.SubDomainList), len(result.AllDomainList), time.Now().Unix()-start.Unix())

	if pushAddress != "" {
		logger.Logger.Info("pushing results to ", pushAddress, ", max pool number:", pushProxyPoolMax)
		Push2Proxy(result.ReqList)
	}

	outputResult(result, isBatchMode)
	return nil
}

func collectRawTargets(c *cli.Context) ([]string, error) {
	rawTargets := c.Args().Slice()
	if inputFilePath == "" {
		if len(rawTargets) == 0 {
			logger.Logger.Error("url must be set")
			return nil, errors.New("url must be set")
		}
		return rawTargets, nil
	}

	fileTargets, err := readTargetsFromFile(inputFilePath)
	if err != nil {
		return nil, err
	}
	rawTargets = append(fileTargets, rawTargets...)
	if len(rawTargets) == 0 {
		logger.Logger.Error("url must be set")
		return nil, errors.New("url must be set")
	}
	return rawTargets, nil
}

func readTargetsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

func buildTargets(rawTargets []string) []*model2.Request {
	var targets []*model2.Request
	for _, _url := range rawTargets {
		var req model2.Request
		url, err := model2.GetUrl(_url)
		if err != nil {
			logger.Logger.Error("parse url failed, ", err)
			continue
		}
		if postData != "" {
			req = model2.GetRequest(config.POST, url, getOption())
		} else {
			req = model2.GetRequest(config.GET, url, getOption())
		}
		req.Proxy = taskConfig.Proxy
		targets = append(targets, &req)
	}
	return targets
}

func runBatchTasks(targets []*model2.Request) *pkg.Result {
	var merged pkg.Result
	logger.Logger.Infof("Start batch crawling, target count: %d", len(targets))
	for index, target := range targets {
		task, err := pkg.NewCrawlerTask([]*model2.Request{target}, taskConfig)
		if err != nil {
			logger.Logger.Error("create crawler task failed: ", err)
			continue
		}
		logger.Logger.Infof("Batch progress: %d/%d, crawling %s", index+1, len(targets), target.URL.String())
		task.Run()
		mergeResult(&merged, task.Result)
	}

	merged.ReqList = deduplicateRequests(merged.ReqList)
	merged.AllReqList = deduplicateRequests(merged.AllReqList)
	merged.AllDomainList = pkg.AllDomainCollect(merged.AllReqList)
	merged.SubDomainList = uniqueStringSlice(merged.SubDomainList)
	return &merged
}

func mergeResult(dst *pkg.Result, src *pkg.Result) {
	dst.ReqList = append(dst.ReqList, src.ReqList...)
	dst.AllReqList = append(dst.AllReqList, src.AllReqList...)
	dst.AllDomainList = append(dst.AllDomainList, src.AllDomainList...)
	dst.SubDomainList = append(dst.SubDomainList, src.SubDomainList...)
}

func deduplicateRequests(reqs []*model2.Request) []*model2.Request {
	seen := make(map[string]struct{})
	var result []*model2.Request
	for _, req := range reqs {
		id := req.UniqueId()
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, req)
	}
	return result
}

func uniqueStringSlice(input []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, item := range input {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func getOption() model2.Options {
	var option model2.Options
	if postData != "" {
		option.PostData = postData
	}
	if taskConfig.ExtraHeadersString != "" {
		err := json.Unmarshal([]byte(taskConfig.ExtraHeadersString), &taskConfig.ExtraHeaders)
		if err != nil {
			logger.Logger.Fatal("custom headers can't be Unmarshal.")
			panic(err)
		}
		option.Headers = taskConfig.ExtraHeaders
	}
	return option
}

func parseCustomFormValues(customData []string) (map[string]string, error) {
	parsedData := map[string]string{}
	for _, item := range customData {
		keyValue := strings.Split(item, "=")
		if len(keyValue) < 2 {
			return nil, errors.New("invalid form item: " + item)
		}
		key := keyValue[0]
		if !tools.StringSliceContain(config.AllowedFormName, key) {
			return nil, errors.New("not allowed form key: " + key)
		}
		value := keyValue[1]
		parsedData[key] = value
	}
	return parsedData, nil
}

func keywordStringToMap(data []string) (map[string]string, error) {
	parsedData := map[string]string{}
	for _, item := range data {
		keyValue := strings.Split(item, "=")
		if len(keyValue) < 2 {
			return nil, errors.New("invalid keyword format: " + item)
		}
		key := keyValue[0]
		value := keyValue[1]
		parsedData[key] = value
	}
	return parsedData, nil
}

func outputResult(result *pkg.Result, isBatchMode bool) {
	if outputMode == "json" {
		fmt.Println("--[Mission Complete]--")
		resBytes := getJsonSerialize(result)
		fmt.Println(string(resBytes))
	} else if outputMode == "txt" {
		writeTxtResult(result, isBatchMode)
	} else if outputMode == "console" {
		for _, req := range result.ReqList {
			req.FormatPrint()
		}
	}
	if len(outputJsonPath) != 0 {
		resBytes := getJsonSerialize(result)
		tools.WriteFile(outputJsonPath, resBytes)
	}
	if len(outputTxtPath) != 0 && outputMode != "txt" {
		writeTxtResult(result, isBatchMode)
	}
}

func writeTxtResult(result *pkg.Result, isBatchMode bool) {
	if len(outputTxtPath) == 0 {
		if isBatchMode {
			outputTxtPath = "crawlergo_batch_result.txt"
		} else {
			outputTxtPath = "crawlergo_result.txt"
		}
	}
	content := getTXTSerialize(result)
	err := os.WriteFile(outputTxtPath, []byte(content), 0644)
	if err != nil {
		logger.Logger.Error("write txt result failed: ", err)
		return
	}
	logger.Logger.Infof("txt result written to %s", outputTxtPath)
}

func getTXTSerialize(result *pkg.Result) string {
	var builder strings.Builder
	for _, req := range result.ReqList {
		builder.WriteString(req.SimpleFormat())
		builder.WriteString("\n")
	}
	return builder.String()
}

func Push2Proxy(reqList []*model2.Request) {
	pool, _ := ants.NewPool(pushProxyPoolMax)
	defer pool.Release()
	for _, req := range reqList {
		task := ProxyTask{
			req:       req,
			pushProxy: pushAddress,
		}
		pushProxyWG.Add(1)
		go func() {
			err := pool.Submit(task.doRequest)
			if err != nil {
				logger.Logger.Error("add Push2Proxy task failed: ", err)
				pushProxyWG.Done()
			}
		}()
	}
	pushProxyWG.Wait()
}

func (p *ProxyTask) doRequest() {
	defer pushProxyWG.Done()
	_, _ = requests.Request(p.req.Method, p.req.URL.String(), tools.ConvertHeaders(p.req.Headers), []byte(p.req.PostData),
		&requests.ReqOptions{Timeout: 1, AllowRedirect: false, Proxy: p.pushProxy})
}

func handleExit(t *pkg.CrawlerTask) {
	<-signalChan
	fmt.Println("exit ...")
	t.Pool.Tune(1)
	t.Pool.Release()
	t.Browser.Close()
	os.Exit(-1)
}

func getJsonSerialize(result *pkg.Result) []byte {
	var res Result
	var reqList []Request
	var allReqList []Request
	for _, _req := range result.ReqList {
		var req Request
		req.Method = _req.Method
		req.Url = _req.URL.String()
		req.Source = _req.Source
		req.Data = _req.PostData
		req.Headers = _req.Headers
		reqList = append(reqList, req)
	}
	for _, _req := range result.AllReqList {
		var req Request
		req.Method = _req.Method
		req.Url = _req.URL.String()
		req.Source = _req.Source
		req.Data = _req.PostData
		req.Headers = _req.Headers
		allReqList = append(allReqList, req)
	}
	res.AllReqList = allReqList
	res.ReqList = reqList
	res.AllDomainList = result.AllDomainList
	res.SubDomainList = result.SubDomainList

	resBytes, err := json.Marshal(res)
	if err != nil {
		log.Fatal("Marshal result error")
	}
	return resBytes
}
