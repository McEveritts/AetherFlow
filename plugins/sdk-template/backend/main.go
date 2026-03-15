package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"aetherflow-plugin-{{PLUGIN_ID}}/internal/aetherflow"
)

func main() {
	client := aetherflow.NewClient(
		os.Getenv("AETHERFLOW_API_BASE_URL"),
		os.Getenv("AETHERFLOW_PLUGIN_TOKEN"),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"plugin": "{{PLUGIN_ID}}",
		})
	})

	mux.HandleFunc("/snapshot", func(w http.ResponseWriter, r *http.Request) {
		payload, err := client.GetJSON(r.Context(), "/api/system/metrics")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	})

	port := os.Getenv("PLUGIN_PORT")
	if port == "" {
		port = "9123"
	}

	log.Printf("starting {{PLUGIN_ID}} backend on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
