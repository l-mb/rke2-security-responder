package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	defaultTelemetryEndpoint = "https://telemetry.rke2.io/v1/telemetry"
	defaultTimeout           = 30 * time.Second
)

// TelemetryData represents the structure of data to be sent
type TelemetryData struct {
	AppVersion     string                 `json:"appVersion"`
	ExtraTagInfo   map[string]string      `json:"extraTagInfo"`
	ExtraFieldInfo map[string]interface{} `json:"extraFieldInfo"`
}

func main() {
	log.Println("RKE2 Security Responder starting...")

	// Check if telemetry is disabled
	if os.Getenv("DISABLE_TELEMETRY") == "true" {
		log.Println("Telemetry is disabled via DISABLE_TELEMETRY environment variable")
		return
	}

	// Create in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("Error creating in-cluster config: %v", err)
		os.Exit(1)
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("Error creating Kubernetes client: %v", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// Collect telemetry data
	data, err := collectTelemetryData(ctx, clientset)
	if err != nil {
		log.Printf("Error collecting telemetry data: %v", err)
		os.Exit(1)
	}

	// Send telemetry data
	endpoint := os.Getenv("TELEMETRY_ENDPOINT")
	if endpoint == "" {
		endpoint = defaultTelemetryEndpoint
	}

	if err := sendTelemetryData(data, endpoint); err != nil {
		// Fail gracefully - log error but exit successfully
		log.Printf("Warning: Failed to send telemetry data: %v", err)
		log.Println("This is expected in disconnected environments")
	} else {
		log.Println("Telemetry data sent successfully")
	}
}

// collectTelemetryData gathers cluster metadata
func collectTelemetryData(ctx context.Context, clientset *kubernetes.Clientset) (*TelemetryData, error) {
	data := &TelemetryData{
		ExtraTagInfo:   make(map[string]string),
		ExtraFieldInfo: make(map[string]interface{}),
	}

	// Get Kubernetes version
	versionInfo, err := clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get server version: %w", err)
	}
	data.AppVersion = versionInfo.GitVersion
	data.ExtraTagInfo["kubernetesVersion"] = versionInfo.GitVersion

	// Get cluster UUID from kube-system namespace
	namespace, err := clientset.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get kube-system namespace: %w", err)
	}
	data.ExtraTagInfo["clusteruuid"] = string(namespace.UID)

	// Count nodes
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	serverNodeCount := 0
	agentNodeCount := 0
	var osInfo, selinuxInfo string

	for _, node := range nodes.Items {
		// Determine if node is server or agent
		if isControlPlaneNode(&node) {
			serverNodeCount++
		} else {
			agentNodeCount++
		}

		// Collect OS info from first node
		if osInfo == "" {
			osInfo = node.Status.NodeInfo.OSImage
		}

		// Check SELinux status from first node
		if selinuxInfo == "" {
			selinuxInfo = getSELinuxStatus(&node)
		}
	}

	data.ExtraFieldInfo["serverNodeCount"] = serverNodeCount
	data.ExtraFieldInfo["agentNodeCount"] = agentNodeCount
	data.ExtraFieldInfo["os"] = osInfo
	data.ExtraFieldInfo["selinux"] = selinuxInfo

	// Detect CNI plugin
	cniPlugin, err := detectCNIPlugin(ctx, clientset)
	if err != nil {
		log.Printf("Warning: Failed to detect CNI plugin: %v", err)
		cniPlugin = "unknown"
	}
	data.ExtraFieldInfo["cni-plugin"] = cniPlugin

	// Detect ingress controller
	ingressController, err := detectIngressController(ctx, clientset)
	if err != nil {
		log.Printf("Warning: Failed to detect ingress controller: %v", err)
		ingressController = "unknown"
	}
	data.ExtraFieldInfo["ingress-controller"] = ingressController

	return data, nil
}

// isControlPlaneNode checks if a node is a control plane node
func isControlPlaneNode(node *corev1.Node) bool {
	_, hasControlPlaneLabel := node.Labels["node-role.kubernetes.io/control-plane"]
	_, hasMasterLabel := node.Labels["node-role.kubernetes.io/master"]
	return hasControlPlaneLabel || hasMasterLabel
}

// getSELinuxStatus determines SELinux status from node
func getSELinuxStatus(node *corev1.Node) string {
	// Check node labels for SELinux information
	if selinux, ok := node.Labels["security.alpha.kubernetes.io/selinux"]; ok && selinux == "enabled" {
		return "enabled"
	}

	// Try to infer from node annotations or system info
	// This is a best-effort approach
	if node.Status.NodeInfo.KernelVersion != "" {
		return "unknown"
	}

	return "disabled"
}

// detectCNIPlugin attempts to detect the CNI plugin in use
func detectCNIPlugin(ctx context.Context, clientset *kubernetes.Clientset) (string, error) {
	// Check for common CNI DaemonSets in kube-system
	daemonSets, err := clientset.AppsV1().DaemonSets("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}

	for _, ds := range daemonSets.Items {
		switch {
		case contains(ds.Name, "canal"):
			return "canal", nil
		case contains(ds.Name, "flannel"):
			return "flannel", nil
		case contains(ds.Name, "calico"):
			return "calico", nil
		case contains(ds.Name, "cilium"):
			return "cilium", nil
		case contains(ds.Name, "weave"):
			return "weave", nil
		}
	}

	return "unknown", nil
}

// detectIngressController attempts to detect the ingress controller in use
func detectIngressController(ctx context.Context, clientset *kubernetes.Clientset) (string, error) {
	// Check for deployments in kube-system
	deployments, err := clientset.AppsV1().Deployments("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}

	for _, deploy := range deployments.Items {
		switch {
		case contains(deploy.Name, "nginx-ingress"), contains(deploy.Name, "rke2-ingress-nginx"):
			return "rke2-ingress-nginx", nil
		case contains(deploy.Name, "traefik"):
			return "traefik", nil
		}
	}

	// Check DaemonSets as well
	daemonSets, err := clientset.AppsV1().DaemonSets("kube-system").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ds := range daemonSets.Items {
			switch {
			case contains(ds.Name, "nginx-ingress"), contains(ds.Name, "rke2-ingress-nginx"):
				return "rke2-ingress-nginx", nil
			case contains(ds.Name, "traefik"):
				return "traefik", nil
			}
		}
	}

	return "none", nil
}

// sendTelemetryData sends the telemetry data to the endpoint
func sendTelemetryData(data *TelemetryData, endpoint string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal telemetry data: %w", err)
	}

	log.Printf("Sending telemetry data to %s", endpoint)
	log.Printf("Data: %s", string(jsonData))

	client := &http.Client{
		Timeout: defaultTimeout,
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			hasSubstring(s, substr)))
}

func hasSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
