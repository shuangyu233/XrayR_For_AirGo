package airgo

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/XrayR-project/XrayR/api"
	"github.com/go-resty/resty/v2"
)

type APIClient struct {
	client        *resty.Client
	APIHost       string
	NodeID        int
	Key           string
	NodeType      string
	EnableVless   bool
	VlessFlow     string
	SpeedLimit    float64
	DeviceLimit   int
	LocalRuleList []api.DetectRule
	eTags         map[string]string
}

// 改进的Show函数，处理可能的序列化错误
func Show(data any) {
	b, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal data: %v", err)
		return
	}
	fmt.Println("data:", string(b))
}

func New(apiConfig *api.Config) *APIClient {
	client := resty.New().
		SetRetryCount(5).
		SetTimeout(time.Duration(apiConfig.Timeout)*time.Second).
		SetBaseURL(apiConfig.APIHost).
		SetQueryParam("key", apiConfig.Key).
		OnError(func(req *resty.Request, err error) {
			if v, ok := err.(*resty.ResponseError); ok {
				log.Print(v.Err)
			}
		})

	localRuleList := readLocalRuleList(apiConfig.RuleListPath)
	return &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		NodeType:      apiConfig.NodeType,
		EnableVless:   apiConfig.EnableVless,
		VlessFlow:     apiConfig.VlessFlow,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
		eTags:         make(map[string]string),
	}
}

// 改进的readLocalRuleList函数，增加了文件打开的nil判断
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {
	LocalRuleList = make([]api.DetectRule, 0)
	if path == "" {
		return LocalRuleList
	}

	file, err := os.Open(path)
	if err != nil {
		log.Printf("Error when opening file: %s", err)
		return LocalRuleList
	}
	defer file.Close()

	fileScanner := bufio.NewScanner(file)
	for fileScanner.Scan() {
		LocalRuleList = append(LocalRuleList, api.DetectRule{
			ID:      -1,
			Pattern: regexp.MustCompile(fileScanner.Text()),
		})
	}

	if err := fileScanner.Err(); err != nil {
		log.Fatalf("Error while reading file: %s", err)
	}

	return LocalRuleList
}

// 抽取 ETag 更新为单独的函数
func updateETag(c *APIClient, res *resty.Response, key string) {
	etag := res.Header().Get("Etag")
	if etag != "" && etag != c.eTags[key] {
		c.eTags[key] = etag
	}
}

// 在GetNodeInfo和GetUserList中使用updateETag
func (c *APIClient) GetNodeInfo() (*api.NodeInfo, error) {
	path := "/api/public/airgo/node/getNodeInfo"
	res, err := c.client.R().
		SetQueryParams(map[string]string{
			"id": fmt.Sprintf("%d", c.NodeID),
		}).
		SetHeader("If-None-Match", c.eTags["node"]).
		ForceContentType("application/json").
		Get(path)

	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}

	updateETag(c, res, "node")

	var nodeInfoResponse NodeInfoResponse
	if err = json.Unmarshal(res.Body(), &nodeInfoResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal node info: %v", err)
	}

	nodeInfo, err := c.ParseAirGoNodeInfo(&nodeInfoResponse)
	if err != nil {
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %v", res.String(), err)
	}

	// 处理rule...
	return nodeInfo, nil
}

func (c *APIClient) GetUserList() (*[]api.UserInfo, error) {
	path := "/api/public/airgo/user/getUserlist"
	res, err := c.client.R().
		SetQueryParams(map[string]string{
			"id": fmt.Sprintf("%d", c.NodeID),
		}).
		SetHeader("If-None-Match", c.eTags["userlist"]).
		ForceContentType("application/json").
		Get(path)

	if err != nil {
		return nil, fmt.Errorf("failed to get user list: %w", err)
	}

	if res.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}

	updateETag(c, res, "userlist")

	var userResponse []UserResponse
	if err = json.Unmarshal(res.Body(), &userResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user list response: %w", err)
	}

	userInfo := make([]api.UserInfo, len(userResponse))
	for i, v := range userResponse {
		speedLimit := calculateSpeedLimit(v.NodeSpeedLimit, c.SpeedLimit)
		userInfo[i] = api.UserInfo{
			UID:         int(v.ID),
			UUID:        v.UUID,
			Email:       v.UserName,
			Passwd:      v.Passwd,
			SpeedLimit:  speedLimit,
			DeviceLimit: int(v.NodeConnector),
		}
	}

	return &userInfo, nil
}

func calculateSpeedLimit(nodeSpeedLimit int64, defaultSpeedLimit float64) uint64 {
	if nodeSpeedLimit > 0 {
		return uint64((float64(nodeSpeedLimit) * 1000000) / 8)
	}
	return uint64((defaultSpeedLimit * 1000000) / 8)
}

func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList
	return &ruleList, nil
}

func (c *APIClient) ParseAirGoNodeInfo(n *NodeInfoResponse) (*api.NodeInfo, error) {
	var nodeInfo api.NodeInfo
	var speedLimit uint64
	var enableTLS bool = true
	var enableREALITY bool = false
	var realityConfig = &api.REALITYConfig{}
	var h = make(map[string]any)
	var header json.RawMessage

	if n.NodeSpeedLimit > 0 {
		speedLimit = uint64((n.NodeSpeedLimit * 1000000) / 8)
	} else {
		speedLimit = uint64((c.SpeedLimit * 1000000) / 8)
	}
	if n.Security == "none" || n.Security == "" {
		enableTLS = false
	}
	if n.Security == "reality" {
		enableREALITY = true
		realityConfig = &api.REALITYConfig{
			Dest:             n.Dest,
			ProxyProtocolVer: 0,
			ServerNames:      []string{n.Sni},
			PrivateKey:       n.PrivateKey,
			MinClientVer:     "",
			MaxClientVer:     "",
			MaxTimeDiff:      0,
			ShortIds:         []string{"", "0123456789abcdef"},
		}
	}

	switch n.Protocol {
	case "vless", "Vless":
		nodeInfo = api.NodeInfo{
			EnableVless:       true,
			VlessFlow:         n.VlessFlow,
			NodeType:          c.NodeType,
			NodeID:            c.NodeID,
			Port:              uint32(n.Port),
			SpeedLimit:        speedLimit,
			TransportProtocol: n.Network,
			EnableTLS:         enableTLS,
			Path:              n.Path,
			Host:              n.Host,
			ServiceName:       n.ServiceName,
			EnableREALITY:     enableREALITY,
			REALITYConfig:     realityConfig,
		}
		switch n.Network {
		case "grpc":
		case "ws":
		case "tcp":
			if n.Type == "http" {
				h = map[string]any{
					"type": "http",
					"request": map[string]any{
						"path": []string{
							n.Path,
						},
						"headers": map[string]any{
							"Host": []string{
								n.Host,
							},
						},
					},
				}
				header, _ = json.Marshal(h)
				nodeInfo.Header = header
			}
		}
	case "vmess", "Vmess":
		nodeInfo = api.NodeInfo{
			EnableVless:       false,
			NodeType:          c.NodeType,
			NodeID:            c.NodeID,
			Port:              uint32(n.Port),
			SpeedLimit:        speedLimit,
			AlterID:           0,
			TransportProtocol: n.Network,
			EnableTLS:         enableTLS,
			Path:              n.Path,
			Host:              n.Host,
			CypherMethod:      n.Scy,
			ServiceName:       n.ServiceName,
			EnableREALITY:     enableREALITY,
		}
		switch n.Network {
		case "grpc":
		case "ws":
		case "tcp":
			if n.Type == "http" {
				h = map[string]any{
					"type": "http",
					"request": map[string]any{
						"path": []string{
							n.Path,
						},
						"headers": map[string]any{
							"Host": []string{
								n.Host,
							},
						},
					},
				}
				header, _ = json.Marshal(h)
				nodeInfo.Header = header
			}
		}
	case "Shadowsocks", "shadowsocks":
		nodeInfo = api.NodeInfo{
			NodeType:          c.NodeType,
			NodeID:            c.NodeID,
			Port:              uint32(n.Port),
			SpeedLimit:        speedLimit,
			TransportProtocol: "tcp",
			CypherMethod:      n.Scy,
			ServerKey:         n.ServerKey,
		}
		if n.Type == "http" {
			h = map[string]any{
				"type": "http",
				"request": map[string]any{
					"path": []string{
						n.Path,
					},
					"headers": map[string]any{
						"Host": []string{
							n.Host,
						},
					},
				},
			}
			header, _ = json.Marshal(h)
			nodeInfo.Header = header
		}
	}
	return &nodeInfo, nil
}

func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) error {
	path := "/api/public/airgo/node/reportNodeStatus"
	nodeStatusRequest := NodeStatusRequest{
		ID:     c.NodeID,
		CPU:    nodeStatus.CPU,
		Mem:    nodeStatus.Mem,
		Disk:   nodeStatus.Disk,
		Uptime: nodeStatus.Uptime,
	}

	return c.postRequest(path, nodeStatusRequest)
}

func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	path := "/api/public/airgo/user/reportUserTraffic"
	userTrafficRequest := UserTrafficRequest{
		ID:          c.NodeID,
		UserTraffic: *userTraffic,
	}

	return c.postRequest(path, userTrafficRequest)
}

func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	onlineUser := OnlineUser{
		NodeID:      c.NodeID,
		UserNodeMap: make(map[int][]string),
	}

	for _, v := range *onlineUserList {
		onlineUser.UserNodeMap[v.UID] = append(onlineUser.UserNodeMap[v.UID], v.IP)
	}

	path := "/api/public/airgo/user/AGReportNodeOnlineUsers"
	return c.postRequest(path, onlineUser)
}
func (c *APIClient) postRequest(path string, body any) error {
	res, err := c.client.R().
		SetBody(body).
		ForceContentType("application/json").
		Post(path)

	if err != nil {
		return fmt.Errorf("failed to send request to %s: %w", c.assembleURL(path), err)
	}

	if res.StatusCode() != 200 {
		return fmt.Errorf("request to %s failed with status: %s", c.assembleURL(path), res.Status())
	}

	return nil
}

func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{}
}

func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) (err error) {
	return nil
}
func (c *APIClient) Debug() {}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}
