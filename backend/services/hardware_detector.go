package services

import (
	"log/slog"
	"os"
	"strings"
)

// GPUFlags contains the hardware-specific ffmpeg arguments
type GPUFlags struct {
	HWAccel       string
	HWAccelDevice string
	OutputFormat  string
	VideoCodec    string
}

// GetGPUTranscodeFlags reads sysfs to determine if AMD or Intel hardware is present.
func GetGPUTranscodeFlags() GPUFlags {
	vendorPath := "/sys/class/drm/renderD128/device/vendor"
	
	data, err := os.ReadFile(vendorPath)
	if err != nil {
		slog.Warn("GPU detection failed, falling back to CPU", "error", err, "path", vendorPath)
		return GPUFlags{
			HWAccel:    "", // Software fallback
			VideoCodec: "libx265",
		}
	}

	vendorID := strings.TrimSpace(string(data))
	slog.Info("GPU Vendor Detected", "id", vendorID)

	switch vendorID {
	case "0x1002": // AMD
		return GPUFlags{
			HWAccel:       "vaapi",
			HWAccelDevice: "/dev/dri/renderD128",
			OutputFormat:  "vaapi",
			VideoCodec:    "hevc_vaapi",
		}
	case "0x8086": // Intel
		return GPUFlags{
			HWAccel:       "qsv",
			HWAccelDevice: "/dev/dri/renderD128",
			VideoCodec:    "hevc_qsv",
		}
	default:
		slog.Warn("Unknown GPU vendor, falling back to CPU", "vendorID", vendorID)
		return GPUFlags{
			HWAccel:    "",
			VideoCodec: "libx265",
		}
	}
}
