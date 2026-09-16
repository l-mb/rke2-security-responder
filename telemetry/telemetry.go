package telemetry

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	semver "github.com/Masterminds/semver/v3"
	"github.com/sirupsen/logrus"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	DefaultEndpoint = "https://security-responder.version.rke2.io/v1/checkupgrade"
	defaultTimeout  = 30 * time.Second
	maxRetries      = 3
	retryDelay      = 2 * time.Second
)

var (
	helmChartGVR = schema.GroupVersionResource{
		Group:    "helm.cattle.io",
		Version:  "v1",
		Resource: "helmcharts",
	}
	rancherSettingGVR = schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "settings",
	}
)

type Data struct {
	AppVersion     string                 `json:"appVersion"`
	ExtraTagInfo   map[string]string      `json:"extraTagInfo"`
	ExtraFieldInfo map[string]interface{} `json:"extraFieldInfo"`
}

type Response struct {
	Versions                 []Version `json:"versions"`
	RequestIntervalInMinutes int       `json:"requestIntervalInMinutes"`
}

type Version struct {
	Name                 string            `json:"name"`
	ReleaseDate          string            `json:"releaseDate"`
	MinUpgradableVersion string            `json:"minUpgradableVersion,omitempty"`
	Tags                 []string          `json:"tags,omitempty"`
	ExtraInfo            map[string]string `json:"extraInfo,omitempty"`
}

func Collect(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface, mode string) (*Data, error) {
	data := &Data{
		ExtraTagInfo:   map[string]string{"mode": mode},
		ExtraFieldInfo: make(map[string]interface{}),
	}
	isMinimal := mode == "minimal"

	logrus.Debug("collecting server version")
	versionInfo, err := clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get server version: %w", err)
	}
	data.AppVersion = versionInfo.GitVersion
	logrus.WithField("version", versionInfo.GitVersion).Debug("collected version")

	logrus.Debug("collecting cluster UUID from kube-system namespace")
	namespace, err := clientset.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get kube-system namespace: %w", err)
	}
	data.ExtraTagInfo["clusteruuid"] = string(namespace.UID)
	logrus.WithField("uuid", namespace.UID).Debug("collected cluster UUID")

	logrus.Debug("collecting node information")
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	var serverNodeCount, agentNodeCount, gpuNodeCount int
	var serverCPU, agentCPU, serverMemory, agentMemory int64
	var operatingSystem, osImage, kernelVersion, arch, selinuxInfo, gpuVendor string

	gpuResources := []corev1.ResourceName{"nvidia.com/gpu", "amd.com/gpu", "intel.com/gpu"}
	gpuVendorMap := map[corev1.ResourceName]string{
		"nvidia.com/gpu": "nvidia",
		"amd.com/gpu":    "amd",
		"intel.com/gpu":  "intel",
	}

	nodeInfoConsistent := true
	for _, node := range nodes.Items {
		cpu := node.Status.Allocatable.Cpu().MilliValue()
		mem := node.Status.Allocatable.Memory().Value()
		if isControlPlaneNode(&node) {
			serverNodeCount++
			serverCPU += cpu
			serverMemory += mem
		} else {
			agentNodeCount++
			agentCPU += cpu
			agentMemory += mem
		}
		if osImage == "" {
			operatingSystem = node.Status.NodeInfo.OperatingSystem
			osImage = node.Status.NodeInfo.OSImage
			kernelVersion = node.Status.NodeInfo.KernelVersion
			arch = node.Status.NodeInfo.Architecture
		} else if node.Status.NodeInfo.OperatingSystem != operatingSystem ||
			node.Status.NodeInfo.OSImage != osImage ||
			node.Status.NodeInfo.KernelVersion != kernelVersion ||
			node.Status.NodeInfo.Architecture != arch {
			nodeInfoConsistent = false
		}
		switch s := getSELinuxStatus(&node); {
		case s == "", s == selinuxInfo:
		case selinuxInfo == "":
			selinuxInfo = s
		default:
			selinuxInfo = "mixed"
		}
		for _, res := range gpuResources {
			if qty, ok := node.Status.Allocatable[res]; ok {
				if count, _ := qty.AsInt64(); count > 0 {
					gpuNodeCount++
					if gpuVendor == "" {
						gpuVendor = gpuVendorMap[res]
					}
					break
				}
			}
		}
	}

	if isMinimal {
		data.ExtraFieldInfo["serverNodeCount"] = -1
		data.ExtraFieldInfo["agentNodeCount"] = -1
		data.ExtraFieldInfo["gpuNodeCount"] = -1
		data.ExtraFieldInfo["serverCPU"] = int64(-1)
		data.ExtraFieldInfo["agentCPU"] = int64(-1)
		data.ExtraFieldInfo["serverMemory"] = int64(-1)
		data.ExtraFieldInfo["agentMemory"] = int64(-1)
	} else {
		data.ExtraFieldInfo["serverNodeCount"] = serverNodeCount
		data.ExtraFieldInfo["agentNodeCount"] = agentNodeCount
		data.ExtraFieldInfo["serverCPU"] = serverCPU
		data.ExtraFieldInfo["agentCPU"] = agentCPU
		data.ExtraFieldInfo["serverMemory"] = serverMemory
		data.ExtraFieldInfo["agentMemory"] = agentMemory
		data.ExtraFieldInfo["gpuNodeCount"] = gpuNodeCount
	}
	data.ExtraTagInfo["operating-system"] = operatingSystem
	data.ExtraTagInfo["os"] = osImage
	data.ExtraFieldInfo["kernel"] = kernelVersion
	data.ExtraTagInfo["arch"] = arch
	data.ExtraTagInfo["selinux"] = selinuxInfo
	data.ExtraTagInfo["node-info-consistent"] = strconv.FormatBool(nodeInfoConsistent)
	data.ExtraTagInfo["gpu-vendor"] = cmp.Or(gpuVendor, "none")
	logrus.WithFields(logrus.Fields{
		"server":       serverNodeCount,
		"agent":        agentNodeCount,
		"serverCPU":    serverCPU,
		"agentCPU":     agentCPU,
		"serverMemory": serverMemory,
		"agentMemory":  agentMemory,
		"gpuNodeCount": gpuNodeCount,
	}).Debug("collected nodes")

	logrus.Debug("collecting kube-system workloads")
	kubeSystemDS, err := clientset.AppsV1().DaemonSets("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list kube-system daemonsets: %w", err)
	}
	kubeSystemDeploy, err := clientset.AppsV1().Deployments("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list kube-system deployments: %w", err)
	}

	logrus.Debug("detecting CNI plugin")
	allDS, err := clientset.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list daemonsets: %w", err)
	}
	cniPlugin, cniVersion := detectCNIPlugin(allDS.Items)
	data.ExtraTagInfo["cni-plugin"] = cniPlugin
	data.ExtraTagInfo["cni-version"] = cniVersion
	logrus.WithFields(logrus.Fields{"plugin": cniPlugin, "version": cniVersion}).Debug("detected CNI")

	logrus.Debug("detecting ingress controller")
	ingressController, ingressVersion := detectIngressController(ctx, clientset, kubeSystemDeploy.Items, kubeSystemDS.Items)
	data.ExtraTagInfo["ingress-controller"] = ingressController
	data.ExtraTagInfo["ingress-version"] = ingressVersion
	logrus.WithFields(logrus.Fields{"controller": ingressController, "version": ingressVersion}).Debug("detected ingress")

	logrus.Debug("detecting GPU operator")
	gpuOperator, gpuOperatorVersion := detectGPUOperator(ctx, clientset)
	data.ExtraTagInfo["gpu-operator"] = gpuOperator
	data.ExtraTagInfo["gpu-operator-version"] = gpuOperatorVersion
	logrus.WithFields(logrus.Fields{"operator": gpuOperator, "version": gpuOperatorVersion}).Debug("detected GPU operator")

	logrus.Debug("detecting Rancher Manager")
	rancherRole, rancherVersion, rancherInstallUUID := detectRancherManager(ctx, clientset, dynClient)
	data.ExtraTagInfo["rancher-managed"] = strconv.FormatBool(rancherRole != "none")
	data.ExtraTagInfo["rancher-role"] = rancherRole
	if isMinimal {
		data.ExtraTagInfo["rancher-version"] = "redacted"
		data.ExtraFieldInfo["rancher-install-uuid"] = ""
	} else {
		data.ExtraTagInfo["rancher-version"] = rancherVersion
		if rancherInstallUUID != "" {
			data.ExtraFieldInfo["rancher-install-uuid"] = rancherInstallUUID
		}
	}
	logrus.WithFields(logrus.Fields{"role": rancherRole, "version": rancherVersion, "installUUID": rancherInstallUUID}).Debug("detected Rancher")

	logrus.Debug("detecting Prime distribution flag")
	prime, sysDefaultRegistry := detectPrime(ctx, dynClient)
	data.ExtraTagInfo["rancher-prime"] = prime
	data.ExtraTagInfo["system-default-registry"] = sysDefaultRegistry
	logrus.WithFields(logrus.Fields{"prime": prime, "systemDefaultRegistry": sysDefaultRegistry}).Debug("detected Prime")

	logrus.Debug("detecting IP stack configuration")
	ipStack := detectIPStack(ctx, clientset)
	data.ExtraTagInfo["ip-stack"] = ipStack
	logrus.WithField("ip-stack", ipStack).Debug("detected IP stack")

	// InfluxDB drops empty tag values, so report undetected values as unknown.
	for k, v := range data.ExtraTagInfo {
		if v == "" {
			data.ExtraTagInfo[k] = "unknown"
		}
	}

	return data, nil
}

func Send(ctx context.Context, data *Data, endpoint string) (*Response, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	logrus.WithField("endpoint", endpoint).Info("sending data")
	logrus.WithField("size", len(jsonData)).Debug("request payload")

	client := &http.Client{Timeout: defaultTimeout}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			delay := time.Duration(attempt-1) * retryDelay
			logrus.WithFields(logrus.Fields{"attempt": attempt, "max": maxRetries, "delay": delay}).Info("retrying")
			time.Sleep(delay)
		}

		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to send request: %w", err)
			logrus.WithField("attempt", attempt).WithError(lastErr).Warn("attempt failed")
			continue
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read response: %w", err)
			logrus.WithField("attempt", attempt).WithError(lastErr).Warn("attempt failed")
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
			logrus.WithField("attempt", attempt).WithError(lastErr).Warn("attempt failed")
			continue
		}

		var response Response
		if err := json.Unmarshal(body, &response); err != nil {
			logrus.WithError(err).Warn("failed to parse response")
			logrus.WithField("attempt", attempt).Info("data sent")
			return nil, nil
		}

		newer := filterNewerVersions(response.Versions, data.AppVersion)
		current := filterCurrentVersion(response.Versions, data.AppVersion)
		logrus.WithFields(logrus.Fields{
			"versions":        len(response.Versions),
			"newer":           len(newer),
			"intervalMinutes": response.RequestIntervalInMinutes,
		}).Info("response received")
		logRecommendations(newer, current)

		logrus.WithField("attempt", attempt).Info("data sent")
		return &response, nil
	}

	return nil, lastErr
}

func isControlPlaneNode(node *corev1.Node) bool {
	_, hasControlPlaneLabel := node.Labels["node-role.kubernetes.io/control-plane"]
	_, hasMasterLabel := node.Labels["node-role.kubernetes.io/master"]
	return hasControlPlaneLabel || hasMasterLabel
}

// getSELinuxStatus reports the RKE2 selinux option of a node, which enables
// SELinux support in containerd. RKE2 records the node arguments, including
// config file values, in the node-args annotation, and its RKE2_* environment
// variables in the node-env annotation. An argument overrides the variable.
// Windows nodes and nodes without the node-args annotation return "".
func getSELinuxStatus(node *corev1.Node) string {
	var args []string
	if node.Status.NodeInfo.OperatingSystem == "windows" ||
		json.Unmarshal([]byte(node.Annotations["rke2.io/node-args"]), &args) != nil {
		return ""
	}
	var env map[string]string
	_ = json.Unmarshal([]byte(node.Annotations["rke2.io/node-env"]), &env)
	enabled, _ := strconv.ParseBool(env["RKE2_SELINUX"])
	for i, arg := range args {
		if arg != "--selinux" {
			continue
		}
		enabled = true
		if i+1 < len(args) {
			if b, err := strconv.ParseBool(args[i+1]); err == nil {
				enabled = b
			}
		}
	}
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func parseCVEs(raw string) []string {
	if raw == "" {
		return nil
	}
	var cves []string
	for _, s := range strings.Split(raw, ",") {
		if cve := strings.TrimSpace(s); cve != "" {
			cves = append(cves, cve)
		}
	}
	return cves
}

// isNewerVersion compares versions by release date when available. This prevents
// a semver-higher but older-released build from being treated as a newer upgrade.
// When the date is unavailable or equal, it falls back to semver and RKE2 rebuild
// suffix comparison for consistency with the existing version-ordering rules.
func isNewerVersion(candidate, current string) bool {
	c, err := semver.NewVersion(candidate)
	if err != nil {
		return false
	}
	cur, err := semver.NewVersion(current)
	if err != nil {
		return true // unparseable current → show all
	}

	if c.GreaterThan(cur) {
		return true
	}
	if cur.GreaterThan(c) {
		return false
	}
	return rke2BuildNumber(c.Metadata()) > rke2BuildNumber(cur.Metadata())
}

func isVersionNewer(candidate, current Version) bool {
	candidateDate, candOK := parseVersionDate(candidate.ReleaseDate)
	currentDate, curOK := parseVersionDate(current.ReleaseDate)

	if candOK && curOK {
		if !candidateDate.After(currentDate) {
			return false
		}

		candidateSemver, candSemErr := semver.NewVersion(candidate.Name)
		currentSemver, curSemErr := semver.NewVersion(current.Name)
		if candSemErr == nil && curSemErr == nil {
			return candidateSemver.Major() > currentSemver.Major() ||
				(candidateSemver.Major() == currentSemver.Major() && candidateSemver.Minor() > currentSemver.Minor()) ||
				(candidateSemver.Major() == currentSemver.Major() && candidateSemver.Minor() == currentSemver.Minor() && candidateSemver.Patch() > currentSemver.Patch()) ||
				(candidateSemver.Major() == currentSemver.Major() && candidateSemver.Minor() == currentSemver.Minor() && candidateSemver.Patch() == currentSemver.Patch() && rke2BuildNumber(candidateSemver.Metadata()) > rke2BuildNumber(currentSemver.Metadata()))
		}
		return true
	}

	candidateSemver, candSemErr := semver.NewVersion(candidate.Name)
	currentSemver, curSemErr := semver.NewVersion(current.Name)
	if candSemErr == nil && curSemErr == nil {
		if currentSemver.GreaterThan(candidateSemver) {
			return false
		}
		if candidateSemver.GreaterThan(currentSemver) {
			return true
		}
		return rke2BuildNumber(candidateSemver.Metadata()) > rke2BuildNumber(currentSemver.Metadata())
	}

	if candOK && !curOK {
		return true
	}
	if !candOK && curOK {
		return false
	}
	return isNewerVersion(candidate.Name, current.Name)
}

func parseVersionDate(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func rke2BuildNumber(metadata string) int {
	suffix, ok := strings.CutPrefix(metadata, "rke2r")
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(suffix)
	if err != nil {
		return 0
	}
	return n
}

func filterNewerVersions(versions []Version, current string) []Version {
	currentVersion := Version{Name: current}
	for i := range versions {
		if versions[i].Name == current {
			currentVersion = versions[i]
			break
		}
	}

	out := make([]Version, 0, len(versions))
	for _, v := range versions {
		if v.Name == current {
			continue
		}
		if isVersionNewer(v, currentVersion) {
			out = append(out, v)
		}
	}
	return sortVersionsByReleaseDateDescending(out)
}

func sortVersionsByReleaseDateDescending(versions []Version) []Version {
	out := append([]Version(nil), versions...)
	sort.Slice(out, func(i, j int) bool {
		iTime, iErr := time.Parse(time.RFC3339, out[i].ReleaseDate)
		jTime, jErr := time.Parse(time.RFC3339, out[j].ReleaseDate)
		switch {
		case iErr != nil && jErr != nil:
			return out[i].Name < out[j].Name
		case iErr != nil:
			return false
		case jErr != nil:
			return true
		default:
			return iTime.After(jTime)
		}
	})
	return out
}

func filterCurrentVersion(versions []Version, current string) *Version {
	for i := range versions {
		if versions[i].Name == current {
			return &versions[i]
		}
	}
	return nil
}

func logRecommendations(newer []Version, current *Version) {
	latest := false
	if current != nil {
		for _, tag := range current.Tags {
			if strings.EqualFold(tag, "latest") {
				latest = true
				logrus.Warnf("The installed RKE2 version %s is the latest released version", current.Name)
				break
			}
		}

		if !latest {
			cves := parseCVEs(current.ExtraInfo["cves"])
			if len(cves) > 0 {
				logrus.Warnf("The installed RKE2 version %s includes CVEs. These are the %d most relevant: %s. Please upgrade to a newer version to fix security vulnerabilities", current.Name, len(cves), strings.Join(cves, ", "))
			}
		}
	}

	for _, v := range newer {
		fields := logrus.Fields{"version": v.Name, "releaseDate": v.ReleaseDate}
		if url := v.ExtraInfo["releaseNotesURL"]; url != "" {
			fields["releaseNotesURL"] = url
		}
		logrus.WithFields(fields).Info("available version")
	}
}

// splitImage splits an image reference into repository and tag, and drops a digest.
func splitImage(image string) (repository, tag string) {
	image, _, _ = strings.Cut(image, "@")
	if idx := strings.LastIndex(image, ":"); idx > strings.LastIndex(image, "/") {
		return image[:idx], image[idx+1:]
	}
	return image, ""
}

func extractImageVersion(image string) string {
	_, tag := splitImage(image)
	return tag
}

// detectCNIPlugin matches DaemonSet names in all namespaces, because some CNIs
// do not run in kube-system. For example, the Tigera operator of rke2-calico
// runs calico-node in calico-system.
func detectCNIPlugin(daemonSets []appsv1.DaemonSet) (string, string) {
	cniNames := []string{"canal", "flannel", "calico", "cilium", "antrea", "kube-ovn", "kube-router", "weave"}

	for _, ds := range daemonSets {
		name := strings.ToLower(ds.Name)
		for _, cniName := range cniNames {
			if strings.Contains(name, cniName) {
				version := ""
				if len(ds.Spec.Template.Spec.Containers) > 0 {
					version = extractImageVersion(ds.Spec.Template.Spec.Containers[0].Image)
				}
				return cniName, version
			}
		}
	}

	return "unknown", ""
}

// ingressControllers maps IngressClass controller prefixes to reported names.
var ingressControllers = []struct{ prefix, name string }{
	{"k8s.io/ingress-nginx", "ingress-nginx"},
	{"k8s.io/ingress-gce", "gce"},
	{"traefik.io/", "traefik"},
	{"nginx.org/", "f5-nginx"},
	{"haproxy.org/", "haproxy"},
	{"haproxy-ingress.github.io/", "haproxy-ingress"},
	{"ingress-controllers.konghq.com/", "kong"},
	{"projectcontour.io/", "contour"},
	{"cilium.io/", "cilium"},
	{"istio.io/", "istio"},
	{"ingress.k8s.aws/", "aws-alb"},
	{"azure/application-gateway", "azure-application-gateway"},
	{"apisix.apache.org/", "apisix"},
	{"pomerium.io/", "pomerium"},
}

// detectIngressController reports the RKE2-bundled ingress controller in
// kube-system, and otherwise the controller of the IngressClasses.
func detectIngressController(ctx context.Context, clientset kubernetes.Interface, deployments []appsv1.Deployment, daemonSets []appsv1.DaemonSet) (string, string) {
	for _, deploy := range deployments {
		name := strings.ToLower(deploy.Name)
		var ingressName string
		switch {
		case strings.Contains(name, "nginx-ingress"), strings.Contains(name, "rke2-ingress-nginx"):
			ingressName = "rke2-ingress-nginx"
		case strings.Contains(name, "traefik"):
			ingressName = "traefik"
		}
		if ingressName != "" {
			version := ""
			if len(deploy.Spec.Template.Spec.Containers) > 0 {
				version = extractImageVersion(deploy.Spec.Template.Spec.Containers[0].Image)
			}
			return ingressName, version
		}
	}

	for _, ds := range daemonSets {
		name := strings.ToLower(ds.Name)
		var ingressName string
		switch {
		case strings.Contains(name, "nginx-ingress"), strings.Contains(name, "rke2-ingress-nginx"):
			ingressName = "rke2-ingress-nginx"
		case strings.Contains(name, "traefik"):
			ingressName = "traefik"
		}
		if ingressName != "" {
			version := ""
			if len(ds.Spec.Template.Spec.Containers) > 0 {
				version = extractImageVersion(ds.Spec.Template.Spec.Containers[0].Image)
			}
			return ingressName, version
		}
	}

	return detectIngressClass(ctx, clientset)
}

// detectIngressClass reports the controller of the default IngressClass, or of
// the first IngressClass with a known controller. The version is unknown.
// Unknown controllers report as "other", so that custom names stay private.
func detectIngressClass(ctx context.Context, clientset kubernetes.Interface) (string, string) {
	classes, err := clientset.NetworkingV1().IngressClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		logrus.WithError(err).Warn("failed to list IngressClasses")
		return "unknown", "unknown"
	}
	if len(classes.Items) == 0 {
		return "none", "none"
	}
	controller := "other"
	for i := range classes.Items {
		name := "other"
		for _, c := range ingressControllers {
			if strings.HasPrefix(classes.Items[i].Spec.Controller, c.prefix) {
				name = c.name
				break
			}
		}
		if classes.Items[i].Annotations[networkingv1.AnnotationIsDefaultIngressClass] == "true" {
			return name, "unknown"
		}
		if controller == "other" {
			controller = name
		}
	}
	return controller, "unknown"
}

func detectGPUOperator(ctx context.Context, clientset kubernetes.Interface) (string, string) {
	gpuNamespaces := map[string]string{
		"gpu-operator":              "nvidia-gpu-operator",
		"kube-amd-gpu":              "amd-gpu-operator",
		"inteldeviceplugins-system": "intel-device-plugins",
	}

	for ns, operator := range gpuNamespaces {
		daemonSets, err := clientset.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, ds := range daemonSets.Items {
			name := strings.ToLower(ds.Name)
			if strings.Contains(name, "device-plugin") || strings.Contains(name, "driver") {
				version := ""
				if len(ds.Spec.Template.Spec.Containers) > 0 {
					version = extractImageVersion(ds.Spec.Template.Spec.Containers[0].Image)
				}
				return operator, version
			}
		}
	}

	return "none", "none"
}

// detectRancherManager classifies the cluster by the Rancher images in
// cattle-system. The role is "downstream" when cattle-cluster-agent connects
// the cluster to a Rancher Manager, and "server" when the cluster runs Rancher
// Manager itself. Rancher does not deploy its agent on its own cluster.
func detectRancherManager(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) (role, version, installUUID string) {
	if _, err := clientset.CoreV1().Namespaces().Get(ctx, "cattle-system", metav1.GetOptions{}); err != nil {
		return "none", "none", ""
	}
	deployments, err := clientset.AppsV1().Deployments("cattle-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		logrus.WithError(err).Warn("failed to list cattle-system deployments")
		return "unknown", "", ""
	}

	role = "unknown"
	for _, deploy := range deployments.Items {
		for _, container := range deploy.Spec.Template.Spec.Containers {
			repository, tag := splitImage(container.Image)
			switch path.Base(repository) {
			case "rancher-agent":
				env := map[string]string{}
				for _, e := range container.Env {
					env[e.Name] = e.Value
				}
				return "downstream", cmp.Or(env["CATTLE_SERVER_VERSION"], tag), env["CATTLE_INSTALL_UUID"]
			case "rancher":
				role, version = "server", tag
			}
		}
	}
	if role == "server" {
		installUUID = getRancherInstallUUID(ctx, dynClient)
	}
	return role, version, installUUID
}

// getRancherInstallUUID reads the install-uuid setting of the local Rancher Manager.
func getRancherInstallUUID(ctx context.Context, dynClient dynamic.Interface) string {
	if dynClient == nil {
		return ""
	}
	setting, err := dynClient.Resource(rancherSettingGVR).Get(ctx, "install-uuid", metav1.GetOptions{})
	if err != nil {
		logrus.WithError(err).Debug("failed to read the Rancher install-uuid setting")
		return ""
	}
	uuid, _, _ := unstructured.NestedString(setting.Object, "value")
	return uuid
}

// detectIPStack determines the cluster's IP stack configuration from the kubernetes service.
func detectIPStack(ctx context.Context, clientset kubernetes.Interface) string {
	kubeSvc, err := clientset.CoreV1().Services("default").Get(ctx, "kubernetes", metav1.GetOptions{})
	if err != nil {
		logrus.WithError(err).Warn("failed to get kubernetes service for IP stack detection")
		return "unknown"
	}
	if len(kubeSvc.Spec.IPFamilies) == 0 {
		return "unknown"
	}
	hasIPv4, hasIPv6 := false, false
	for _, f := range kubeSvc.Spec.IPFamilies {
		switch f {
		case corev1.IPv4Protocol:
			hasIPv4 = true
		case corev1.IPv6Protocol:
			hasIPv6 = true
		}
	}
	switch {
	case hasIPv4 && hasIPv6:
		return "dual-stack"
	case hasIPv4:
		return "ipv4-only"
	case hasIPv6:
		return "ipv6-only"
	default:
		return "unknown"
	}
}

// detectPrime reads global.prime.enabled and global.systemDefaultRegistry from
// HelmChart spec.set, which RKE2 injects at bootstrap (rancher/rke2#9859).
// Returns "unknown" when the CRD/RBAC/charts are absent or no chart carries the
// key (pre-PR-9859 cluster). Positive wins on HA mismatch. The registry is "none"
// when RKE2 injects it empty, and "" when no chart carries it.
func detectPrime(ctx context.Context, dynClient dynamic.Interface) (string, string) {
	if dynClient == nil {
		return "unknown", ""
	}
	list, err := dynClient.Resource(helmChartGVR).Namespace("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) || apierrors.IsForbidden(err) {
			logrus.WithError(err).Debug("HelmChart CRD or RBAC unavailable; prime=unknown")
			return "unknown", ""
		}
		logrus.WithError(err).Warn("failed to list HelmCharts for Prime detection")
		return "unknown", ""
	}
	state := "unknown"
	var registry string
	registryInjected := false
	for i := range list.Items {
		set, _, _ := unstructured.NestedMap(list.Items[i].Object, "spec", "set")
		if state != "true" {
			if s, ok := set["global.prime.enabled"].(string); ok {
				if b, err := strconv.ParseBool(s); err == nil {
					switch {
					case b:
						state = "true"
					case state == "unknown":
						state = "false"
					}
				}
			}
		}
		if r, ok := set["global.systemDefaultRegistry"].(string); ok {
			registryInjected = true
			registry = cmp.Or(registry, r)
		}
		if state == "true" && registry != "" {
			break
		}
	}
	if registryInjected {
		registry = cmp.Or(registry, "none")
	}
	return state, registry
}
