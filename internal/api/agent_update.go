package api

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// latestAgentVersion returns the version the portal considers "latest". It is set
// manually via the LATEST_AGENT_VERSION env var on the backend (matches whatever
// packages were last deployed via `make deploy-binaries`).
func latestAgentVersion() string {
	v := strings.TrimSpace(os.Getenv("LATEST_AGENT_VERSION"))
	if v == "" {
		return "unknown"
	}
	return v
}

// backendPublicURL is the externally-reachable base URL agents use to download
// packages (fronted by the vsay-auth gateway). Falls back to BACKEND_URL.
func backendPublicURL() string {
	if v := strings.TrimSpace(os.Getenv("BACKEND_PUBLIC_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(os.Getenv("BACKEND_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8082"
}

// detectOSArch parses the agent's reported os_info string
// ("<platform> <version> <kernelArch>", e.g. "ubuntu 22.04 x86_64") into a
// normalized (osName, arch) pair used to pick the correct package.
func detectOSArch(osInfo string) (osName, arch string) {
	lower := strings.ToLower(osInfo)

	switch {
	case strings.Contains(lower, "debian"), strings.Contains(lower, "ubuntu"), strings.Contains(lower, "kali"), strings.Contains(lower, "mint"):
		osName = "debian"
	case strings.Contains(lower, "rocky"), strings.Contains(lower, "rhel"), strings.Contains(lower, "red hat"), strings.Contains(lower, "centos"), strings.Contains(lower, "fedora"), strings.Contains(lower, "alma"):
		osName = "rhel"
	case strings.Contains(lower, "darwin"), strings.Contains(lower, "mac"):
		osName = "darwin"
	case strings.Contains(lower, "windows"):
		osName = "windows"
	default:
		osName = "linux"
	}

	if strings.Contains(lower, "aarch64") || strings.Contains(lower, "arm64") {
		arch = "arm64"
	} else {
		arch = "amd64"
	}
	return osName, arch
}

// selfUpdateURL maps a normalized (osName, arch) to the full download URL of the
// matching agent package. Filenames match those produced by `make deploy-binaries`.
func selfUpdateURL(osName, arch string) string {
	base := backendPublicURL() + "/agent/download/"
	switch osName {
	case "windows":
		if arch == "arm64" {
			return base + "vsay-agent-arm64.exe"
		}
		return base + "vsay-agent-amd64.exe"
	case "darwin":
		if arch == "arm64" {
			return base + "vsay-agent-arm64.dmg"
		}
		return base + "vsay-agent-amd64.dmg"
	case "debian":
		if arch == "arm64" {
			return base + "vsay-agent-arm64.deb"
		}
		return base + "vsay-agent-amd64.deb"
	default: // rhel, rocky, generic linux → tar.gz
		if arch == "arm64" {
			return base + "vsay-agent-aarch64.tar.gz"
		}
		return base + "vsay-agent-x86_64.tar.gz"
	}
}

// agentVersionOf returns the version the machine reported in register metadata.
func agentVersionOf(metadata map[string]string) string {
	if metadata != nil {
		if v := metadata["version"]; v != "" {
			return v
		}
	}
	return "unknown"
}

// CheckAgentUpdate returns the machine's current agent version, the latest available
// version, and whether an update is available.
// GET /api/machines/:agent_id/update-check
func (h *Handler) CheckAgentUpdate(c *gin.Context) {
	agentID := c.Param("agent_id")

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	current := agentVersionOf(machine.Metadata)
	latest := latestAgentVersion()

	// An update is offered when both versions are known and differ.
	updateAvailable := latest != "unknown" && current != "unknown" && current != latest

	c.JSON(http.StatusOK, gin.H{
		"current_version":  current,
		"latest_version":   latest,
		"update_available": updateAvailable,
		"is_connected":     h.agentManager.IsAgentConnected(agentID),
	})
}

// UpdateAgent triggers a self-update on the machine's agent by sending the
// __vsay_update__ command with the package download URL over the gRPC stream.
// POST /api/machines/:agent_id/update
func (h *Handler) UpdateAgent(c *gin.Context) {
	agentID := c.Param("agent_id")

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	if !h.agentManager.IsAgentConnected(agentID) {
		c.JSON(http.StatusConflict, gin.H{"error": "Agent is offline — it must be online to update"})
		return
	}

	osName, arch := detectOSArch(machine.OS)
	downloadURL := selfUpdateURL(osName, arch)

	if err := h.agentManager.SendUpdateCommand(agentID, downloadURL); err != nil {
		h.logger.Error("Failed to send update command",
			zap.String("agent_id", agentID),
			zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send update command: " + err.Error()})
		return
	}

	h.logger.Info("Self-update triggered",
		zap.String("agent_id", agentID),
		zap.String("os", osName),
		zap.String("arch", arch),
		zap.String("url", downloadURL))

	c.JSON(http.StatusOK, gin.H{
		"message":      "Update command sent. The agent will download, update, and restart.",
		"download_url": downloadURL,
		"target_os":    osName,
		"target_arch":  arch,
	})
}
