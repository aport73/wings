package router

import (
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/pterodactyl/wings/system"
)

func getNodeStats(c *gin.Context) {
    stats, err := system.GetNodeMetrics()
    if err != nil {
        c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
            "error": "The metrics could not be obtained for the node",
        })
        return
    }

    var ramPercent, swapPercent, diskPercent float64
    if stats.MemoryTotal > 0 {
        ramPercent = float64(stats.MemoryUsed) / float64(stats.MemoryTotal) * 100
    }
    if stats.SwapTotal > 0 {
        swapPercent = float64(stats.SwapUsed) / float64(stats.SwapTotal) * 100
    }
    if stats.DiskTotal > 0 {
        diskPercent = float64(stats.DiskUsed) / float64(stats.DiskTotal) * 100
    }

    c.JSON(http.StatusOK, gin.H{
        "ram_used":     stats.MemoryUsed,
        "ram_total":    stats.MemoryTotal,
        "ram_percent":  ramPercent,
        "swap_used":    stats.SwapUsed,
        "swap_total":   stats.SwapTotal,
        "swap_percent": swapPercent,

        "disk_used":    stats.DiskUsed,
        "disk_total":   stats.DiskTotal,
        "disk_percent": diskPercent,
        "disk_read":    stats.DiskRead,
        "disk_write":   stats.DiskWrite,
        "disk_read_rate":  stats.DiskReadRate,
        "disk_write_rate": stats.DiskWriteRate,

        "net_in":     stats.NetIn,
        "net_out":    stats.NetOut,
        "net_in_rate":  stats.NetInRate,
        "net_out_rate": stats.NetOutRate,

        "cpu_used":     stats.CPUUsed,
        "cpu_threads":  stats.CPUThreads,
        "cpu_model":    stats.CPUModel,
    })
}
