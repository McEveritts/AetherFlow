import { z } from 'zod';

// A permissive schema for WebSocket incoming messages to avoid breaking the UI
// if the backend adds new fields, while maintaining type safety for existing fields.

export const processInfoSchema = z.object({
    pid: z.number(),
    name: z.string(),
    cpu: z.number(),
    mem: z.number(),
}).passthrough();

export const diskPartitionSchema = z.object({
    mount_point: z.string(),
    device: z.string(),
    fs_type: z.string(),
    total_gb: z.number(),
    used_gb: z.number(),
    free_gb: z.number(),
    used_pct: z.number(),
}).passthrough();

export const systemMetricsSchema = z.object({
    cpu_usage: z.number(),
    per_core_cpu: z.array(z.number()),
    cpu_freq_mhz: z.number(),
    disk_space: z.object({
        total: z.number(),
        used: z.number(),
        free: z.number(),
    }).passthrough(),
    disks: z.array(diskPartitionSchema),
    disk_io: z.object({
        read_bytes_sec: z.number(),
        write_bytes_sec: z.number(),
    }).passthrough(),
    is_windows: z.boolean(),
    services: z.record(
        z.string(),
        z.object({
            status: z.enum(['running', 'stopped', 'error']),
            uptime: z.string(),
            version: z.string().optional(),
        }).passthrough()
    ),
    memory: z.object({
        total: z.number(),
        used: z.number(),
    }).passthrough(),
    swap: z.object({
        total: z.number(),
        used: z.number(),
    }).passthrough(),
    network: z.object({
        down: z.string(),
        up: z.string(),
        active_connections: z.number(),
    }).passthrough(),
    total_net_bytes: z.object({
        rx: z.number(),
        tx: z.number(),
    }).passthrough(),
    uptime: z.string(),
    load_average: z.tuple([z.number(), z.number(), z.number()]).or(z.array(z.number())),
    processes: z.array(processInfoSchema),
}).passthrough();

export const webSocketMessageSchema = z.object({
    type: z.string(),
    data: z.any().optional(), // We handle deeper parsing conditionally
}).passthrough();

export const metricsUpdateDataSchema = z.object({
    system: systemMetricsSchema.nullable().optional(),
    services: z.record(z.string(), z.any()).nullable().optional(),
}).passthrough();
