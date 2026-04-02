package services

import (
	"context"
	"fmt"
	"log"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// PluginManager encapsulates the wazero runtime for executing isolated WebAssembly plugins.
type PluginManager struct {
	runtime wazero.Runtime
}

// NewPluginManager initializes a strict Zero-Trust Wasm runtime.
func NewPluginManager(ctx context.Context) *PluginManager {
	// Create a new WebAssembly Runtime.
	r := wazero.NewRuntime(ctx)

	// Instantiate WASI, which provides isolated system call equivalents (e.g. clock, random).
	// We do NOT expose arbitrary filesystem or network access here by default.
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		log.Printf("Failed to instantiate WASI: %v", err)
	}

	// Mount a strictly controlled host function. Let's allow plugins to log safely to our backend console.
	_, err := r.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithFunc(func(ctx context.Context, mod api.Module, ptr uint32, len uint32) {
			bytes, ok := mod.Memory().Read(ptr, len)
			if !ok {
				log.Printf("[Plugin] Could not read memory for host_log")
				return
			}
			log.Printf("[Plugin Log]: %s", string(bytes))
		}).
		Export("host_log").
		Instantiate(ctx)

	if err != nil {
		log.Printf("Failed to instantiate env module: %v", err)
	}

	return &PluginManager{
		runtime: r,
	}
}

// LoadPluginBytes compiles and instantiates a WebAssembly plugin from raw byte code.
func (pm *PluginManager) LoadPluginBytes(ctx context.Context, name string, wasmBytes []byte) (api.Module, error) {
	// Compile the WebAssembly module
	compiled, err := pm.runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("compile failure: %w", err)
	}

	// Restrict the memory/CPU bound if necessary. Wazero will safely sandbox execution.
	mod, err := pm.runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName(name))
	if err != nil {
		return nil, fmt.Errorf("instantiate failure: %w", err)
	}

	return mod, nil
}

// CallPluginFunc invokes an exported function from the WebAssembly module.
func (pm *PluginManager) CallPluginFunc(ctx context.Context, mod api.Module, funcName string, args ...uint64) (uint64, error) {
	fn := mod.ExportedFunction(funcName)
	if fn == nil {
		return 0, fmt.Errorf("exported function %s not found in plugin", funcName)
	}

	results, err := fn.Call(ctx, args...)
	if err != nil {
		return 0, err
	}

	if len(results) > 0 {
		return results[0], nil
	}
	return 0, nil
}

// Close gracefully shuts down the wazero runtime.
func (pm *PluginManager) Close(ctx context.Context) error {
	return pm.runtime.Close(ctx)
}
