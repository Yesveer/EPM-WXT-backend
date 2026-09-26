package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// GetAccessEvents lists external SSH/RDP login history for a machine, plus the
// currently-active external sessions (for the overview warning banner).
// GET /api/machines/:agent_id/access-events?limit=&skip=
func (h *Handler) GetAccessEvents(c *gin.Context) {
	agentID := c.Param("agent_id")
	userIDStr := c.GetString("user_id")
	username := c.GetString("username")
	role := c.GetString("role")
	userID, _ := primitive.ObjectIDFromHex(userIDStr)

	machine, err := h.store.GetMachineByAgentID(agentID)
	if err != nil || machine == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Machine not found"})
		return
	}

	// Owner, admins, or a granted user may view.
	authorized := machine.OwnerID == userID || role == "company_admin" || role == "super_admin"
	if !authorized {
		for _, u := range machine.AllowedUsers {
			if u == username {
				authorized = true
				break
			}
		}
	}
	if !authorized {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	skip, _ := strconv.Atoi(c.DefaultQuery("skip", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	events, err := h.store.GetAccessEventsByMachine(machine.ID, limit, skip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load access history"})
		return
	}
	active, _ := h.store.GetActiveAccessEvents(machine.ID)
	total, _ := h.store.CountAccessEventsByMachine(machine.ID)

	c.JSON(http.StatusOK, gin.H{
		"events": events,
		"active": active,
		"total":  total,
	})
}
