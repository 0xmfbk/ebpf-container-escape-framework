package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type K8sInfo struct {
	PodName        string
	Namespace      string
	ServiceAccount string
}

type KubeletPodList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			ServiceAccountName string `json:"serviceAccountName"`
		} `json:"spec"`
		Status struct {
			ContainerStatuses []struct {
				ContainerID string `json:"containerID"` // e.g., "containerd://abcdef..."
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

type K8sResolver struct {
	mu    sync.RWMutex
	cache map[string]K8sInfo // Key: ContainerID (without the "containerd://" prefix)

	client *http.Client
	stop   chan struct{}
}

func newK8sResolver() *K8sResolver {
	// Strictly bound the map to prevent memory leaks if someone spams pods
	res := &K8sResolver{
		cache: make(map[string]K8sInfo, 5000),
		stop:  make(chan struct{}),
	}

	// Kubelet uses TLS on 10250. Verify certificates using the Kubernetes CA.
	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	tlsConfig := &tls.Config{
		ServerName: "localhost",
	}

	if caPEM, err := os.ReadFile(caPath); err == nil {
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caPEM); ok {
			tlsConfig.RootCAs = pool
		} else {
			fmt.Printf("warning: failed to parse kube CA cert at %s; using system roots\n", caPath)
		}
	} else {
		fmt.Printf("warning: failed to read kube CA cert at %s: %v; using system roots\n", caPath, err)
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	res.client = &http.Client{
		Transport: tr,
		Timeout:   2 * time.Second, // Fast timeout to prevent hangs
	}

	go res.pollLoop()
	return res
}

func (k *K8sResolver) pollLoop() {
	// If the Kubelet service account token doesn't exist, this isn't a K8s node.
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
		// Not a K8s node. Exit silently.
		return
	}

	ticker := time.NewTicker(10 * time.Second) // Poll every 10s
	defer ticker.Stop()

	for {
		select {
		case <-k.stop:
			return
		case <-ticker.C:
			k.fetchPods(tokenPath)
		}
	}
}

func (k *K8sResolver) fetchPods(tokenPath string) {
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return
	}

	req, err := http.NewRequest("GET", "https://127.0.0.1:10250/pods", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+string(token))

	resp, err := k.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	// Use a streaming JSON decoder to avoid buffering the whole payload in RAM
	var podList KubeletPodList
	if err := json.NewDecoder(resp.Body).Decode(&podList); err != nil {
		return
	}

	newCache := make(map[string]K8sInfo, 5000)
	for _, pod := range podList.Items {
		for _, status := range pod.Status.ContainerStatuses {
			// containerID format is usually "containerd://<id>" or "docker://<id>"
			id := status.ContainerID
			if idx := strings.Index(id, "://"); idx != -1 {
				id = id[idx+3:]
			}
			if id == "" {
				continue
			}
			newCache[id] = K8sInfo{
				PodName:        pod.Metadata.Name,
				Namespace:      pod.Metadata.Namespace,
				ServiceAccount: pod.Spec.ServiceAccountName,
			}
		}
	}

	k.mu.Lock()
	k.cache = newCache
	k.mu.Unlock()
}

func (k *K8sResolver) Lookup(containerID string) (K8sInfo, bool) {
	if containerID == "" {
		return K8sInfo{}, false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	info, ok := k.cache[containerID]
	return info, ok
}

func (k *K8sResolver) Close() {
	close(k.stop)
}
