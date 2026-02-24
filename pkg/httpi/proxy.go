package httpi

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

var ignoredHeaders = map[string]bool{
	"Host":            true,
	"Accept-Encoding": true,
	"Content-Length":  true,
	"Connection":      true,
	"Keep-Alive":      true,
	"Te":              true,
	"Trailers":        true,
	"Upgrade":         true,
}

var bufferPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 4096))
	},
}

type ProxyRequestHook func(req HttpRequest, proxyReq *http.Request) error
type ProxyResponseHook func(req HttpRequest, proxyRes *http.Response) error
type BodyModifierHook func(req HttpRequest, body *map[string]any) error

type HttpProxyConfig struct {
	BaseURL  string
	Rewrites map[string]string
	Headers  map[string]string

	Timeout         time.Duration
	MaxIdleConns    int
	IdleConnTimeout time.Duration
}

type rewriteRule struct {
	match   string
	replace string
}

type HttpProxy struct {
	config HttpProxyConfig
	client *http.Client

	rewriteRules []rewriteRule

	mu      sync.RWMutex
	reqHook []ProxyRequestHook
	resHook []ProxyResponseHook
}

func NewHttpProxy(config HttpProxyConfig) *HttpProxy {
	if config.MaxIdleConns == 0 {
		config.MaxIdleConns = 100
	}
	if config.IdleConnTimeout == 0 {
		config.IdleConnTimeout = 90 * time.Second
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	rules := make([]rewriteRule, 0, len(config.Rewrites))
	for k, v := range config.Rewrites {
		rules = append(rules, rewriteRule{match: k, replace: v})
	}
	sort.Slice(rules, func(i, j int) bool {
		return len(rules[i].match) > len(rules[j].match)
	})

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConns,
		IdleConnTimeout:     config.IdleConnTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &HttpProxy{
		config:       config,
		rewriteRules: rules,
		client: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		},
		reqHook: make([]ProxyRequestHook, 0),
		resHook: make([]ProxyResponseHook, 0),
	}
}

func (proxy *HttpProxy) AddRequestHook(hook ProxyRequestHook) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	proxy.reqHook = append(proxy.reqHook, hook)
}

func (proxy *HttpProxy) AddResponseHook(hook ProxyResponseHook) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	proxy.resHook = append(proxy.resHook, hook)
}

func (proxy *HttpProxy) Handle(req HttpRequest, res HttpResponse, path string) error {
	proxyRes, err := proxy.createAndSendRequest(req, path)
	if err != nil {
		res.SetStatus(http.StatusBadGateway)
		return res.JSON(map[string]any{"error": err.Error()})
	}
	defer proxyRes.Body.Close()

	if len(proxy.resHook) > 0 {
		proxy.mu.RLock()
		for _, hook := range proxy.resHook {
			if err := hook(req, proxyRes); err != nil {
				proxy.mu.RUnlock()
				res.SetStatus(http.StatusInternalServerError)
				return res.JSON(map[string]any{"error": "Response hook error: " + err.Error()})
			}
		}
		proxy.mu.RUnlock()
	}

	copyHeaders(res, proxyRes)
	res.SetStatus(proxyRes.StatusCode)

	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	_, err = buf.ReadFrom(proxyRes.Body)
	if err != nil {
		return err
	}

	return res.Send(buf.Bytes())
}

func (proxy *HttpProxy) HandleWithBodyHook(
	req HttpRequest,
	res HttpResponse,
	path string,
	modifyResBody BodyModifierHook,
) error {
	proxyRes, err := proxy.createAndSendRequest(req, path)
	if err != nil {
		res.SetStatus(http.StatusBadGateway)
		return res.JSON(map[string]any{"error": err.Error()})
	}
	defer proxyRes.Body.Close()

	if modifyResBody == nil {
		copyHeaders(res, proxyRes)
		res.SetStatus(proxyRes.StatusCode)

		buf := bufferPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufferPool.Put(buf)

		buf.ReadFrom(proxyRes.Body)
		return res.Send(buf.Bytes())
	}

	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	if _, err := buf.ReadFrom(proxyRes.Body); err != nil {
		res.SetStatus(http.StatusInternalServerError)
		return res.JSON(map[string]any{"error": "Failed to read body"})
	}

	bodyBytes := buf.Bytes()

	if len(bodyBytes) == 0 {
		res.SetStatus(proxyRes.StatusCode)
		return res.Send(nil)
	}

	var jsonBody map[string]any
	if err := json.Unmarshal(bodyBytes, &jsonBody); err != nil {
		res.SetStatus(http.StatusInternalServerError)
		return res.JSON(map[string]any{
			"error":       "Invalid JSON",
			"status_code": proxyRes.StatusCode,
		})
	}

	if err := modifyResBody(req, &jsonBody); err != nil {
		res.SetStatus(http.StatusInternalServerError)
		return res.JSON(map[string]any{"error": err.Error()})
	}

	res.SetStatus(proxyRes.StatusCode)
	for k, v := range proxyRes.Header {
		if k != "Content-Length" && len(v) > 0 {
			res.SetHeader(k, v[0])
		}
	}

	return res.JSON(jsonBody)
}

func (proxy *HttpProxy) createAndSendRequest(req HttpRequest, path string) (*http.Response, error) {
	finalPath := path
	for _, rule := range proxy.rewriteRules {
		if strings.HasPrefix(finalPath, rule.match) {
			finalPath = strings.Replace(finalPath, rule.match, rule.replace, 1)
			break
		}
	}

	targetURL := proxy.config.BaseURL + finalPath

	query := req.Queries()
	if len(query) > 0 {
		q := "?"
		for k, v := range query {
			q += k + "=" + v + "&"
		}
		targetURL += q[:len(q)-1]
	}

	var bodyReader io.Reader
	body := req.GetBody()
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	proxyReq, err := http.NewRequest(req.GetMethod(), targetURL, bodyReader)
	if err != nil {
		return nil, err
	}

	reqHeaders := req.FiberCtx().GetReqHeaders()
	for k, v := range reqHeaders {
		if !ignoredHeaders[k] {
			proxyReq.Header.Set(k, v[0])
		}
	}
	for k, v := range proxy.config.Headers {
		proxyReq.Header.Set(k, v)
	}

	proxy.mu.RLock()
	for _, hook := range proxy.reqHook {
		if err := hook(req, proxyReq); err != nil {
			proxy.mu.RUnlock()
			return nil, err
		}
	}
	proxy.mu.RUnlock()

	return proxy.client.Do(proxyReq)
}

func copyHeaders(res HttpResponse, proxyRes *http.Response) {
	for k, v := range proxyRes.Header {
		if len(v) > 0 {
			res.SetHeader(k, v[0])
		}
	}
}
