import { z } from 'zod';

// A permissive schema for WebSocket incoming messages to avoid breaking the UI
// if the backend adds new fields, while maintaining type safety for existing fields.
//
// IMPORTANT: Go serializes nil slices/maps as JSON `null`, NOT `undefined`.
// Zod's `.optional()` only accepts `undefined`, so every field that could be
// `null` from the backend MUST also have `.nullable()` to prevent safeParse
// failures that silently drop valid metrics (causing "System Offline").

export const processInfoSchema = z.object({
    pid: z.number().optional(),
    name: z.string().optional(),
    cpu: z.number().optional(),
    mem: z.number().optional(),
}).passthrough();

export const diskPartitionSchema = z.object({
    mount_point: z.string().optional(),
    device: z.string().optional(),
    fs_type: z.string().optional(),
    total_gb: z.number().optional(),
    used_gb: z.number().optional(),
    free_gb: z.number().optional(),
    used_pct: z.number().optional(),
}).passthrough();

export const systemMetricsSchema = z.object({
    // cpu_usage is always sent by the backend but default to 0 if somehow missing
    cpu_usage: z.number().default(0),
    // Go nil slices → JSON null; must accept both null and undefined
    per_core_cpu: z.array(z.number()).nullable().optional(),
    cpu_freq_mhz: z.number().nullable().optional(),
    // Backend sends map[string]float64 for disk_space; also accept array form for forward compat
    disk_space: z.union([z.record(z.string(), z.number()), z.array(diskPartitionSchema)]).nullable().optional(),
    disks: z.array(diskPartitionSchema).nullable().optional(),
    disk_io: z.record(z.string(), z.any()).nullable().optional(),
    is_windows: z.boolean().nullable().optional(),
    // Backend SystemMetrics.Services is map[string]bool; accept any value type for resilience
    services: z.record(z.string(), z.any()).nullable().optional(),
    memory: z.record(z.string(), z.number()).nullable().optional(),
    swap: z.record(z.string(), z.number()).nullable().optional(),
    network: z.record(z.string(), z.any()).nullable().optional(),
    total_net_bytes: z.record(z.string(), z.any()).nullable().optional(),
    uptime: z.string().nullable().optional(),
    load_average: z.array(z.number()).nullable().optional(),
    processes: z.array(processInfoSchema).nullable().optional(),
}).passthrough();

export const webSocketMessageSchema = z.object({
    type: z.string(),
    data: z.any().optional(), // We handle deeper parsing conditionally
}).passthrough();

export const metricsUpdateDataSchema = z.object({
    system: systemMetricsSchema.nullable().optional(),
    services: z.record(z.string(), z.any()).nullable().optional(),
}).passthrough();
