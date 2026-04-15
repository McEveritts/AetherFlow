'use client';

import React, { useEffect, useRef, useMemo } from 'react';
import * as d3 from 'd3';
import { Network } from 'lucide-react';
import { SystemMetrics } from '@/types/dashboard';

interface AppTopologyMapProps {
    metrics: SystemMetrics;
}

interface D3Node extends d3.SimulationNodeDatum {
    id: string;
    group: number;
    status: string;
}

interface D3Link extends d3.SimulationLinkDatum<D3Node> {
    source: string | D3Node;
    target: string | D3Node;
    value: number;
}

export default function AppTopologyMap({ metrics }: AppTopologyMapProps) {
    const svgRef = useRef<SVGSVGElement>(null);
    const simulationRef = useRef<d3.Simulation<D3Node, D3Link> | null>(null);
    const nodesRef = useRef<D3Node[]>([]);
    const linksRef = useRef<D3Link[]>([]);

    useEffect(() => {
        if (!svgRef.current) return;

        const width = svgRef.current.parentElement?.clientWidth || 800;
        const height = 400;

        // 1. Setup SVG only once
        const svg = d3.select(svgRef.current)
            .attr('width', '100%')
            .attr('height', height)
            .attr('viewBox', [0, 0, width, height]);

        if (svg.select('g.container').empty()) {
            const container = svg.append("g").attr("class", "container");
            container.append("g").attr("class", "links");
            container.append("g").attr("class", "nodes");
            container.append("g").attr("class", "labels");

            const zoom = d3.zoom<SVGSVGElement, unknown>()
                .scaleExtent([0.5, 4])
                .on("zoom", (event) => {
                    container.attr("transform", event.transform);
                });

            svg.call(zoom);
        }

        // 2. Initialize simulation only once
        if (!simulationRef.current) {
            simulationRef.current = d3.forceSimulation<D3Node, D3Link>()
                .force("link", d3.forceLink<D3Node, D3Link>().id((d: any) => d.id).distance(120))
                .force("charge", d3.forceManyBody().strength(-400))
                .force("center", d3.forceCenter(width / 2, height / 2))
                .force("collide", d3.forceCollide().radius(40));

            // Tooltip setup (once)
            if (d3.select("body").select(".d3-tooltip").empty()) {
                d3.select("body").append("div")
                    .attr("class", "d3-tooltip absolute opacity-0 bg-slate-900 border border-white/10 p-2 rounded-lg text-xs text-white shadow-xl pointer-events-none z-[100] font-mono");
            }
        }

        const simulation = simulationRef.current;

        // 3. Update Data Pattern
        const updateGraph = () => {
            // Build current node set
            const newNodes: D3Node[] = [{ id: 'AetherFlow Core', group: 1, status: 'running' }];
            const newLinks: D3Link[] = [];

            if (metrics.services) {
                Object.entries(metrics.services).forEach(([name, info]) => {
                    newNodes.push({ id: name, group: 2, status: info.status });
                    newLinks.push({ source: 'AetherFlow Core', target: name, value: 1 });
                });
            }
            
            // Dummy nodes
            newNodes.push({ id: 'Proxy Port 8080', group: 3, status: 'running' });
            newNodes.push({ id: 'Nginx Router', group: 3, status: 'running' });
            newNodes.push({ id: 'PostgreSQL DB', group: 4, status: 'running' });
            newNodes.push({ id: 'Redis Cache', group: 4, status: 'running' });

            newLinks.push({ source: 'Proxy Port 8080', target: 'Nginx Router', value: 2 });
            newLinks.push({ source: 'Nginx Router', target: 'AetherFlow Core', value: 2 });
            newLinks.push({ source: 'AetherFlow Core', target: 'PostgreSQL DB', value: 2 });
            newLinks.push({ source: 'AetherFlow Core', target: 'Redis Cache', value: 2 });

            // Diffing nodes to preserve coordinates (Crucial fix for jitter)
            const existingNodes = nodesRef.current;
            const mergedNodes = newNodes.map(newNode => {
                const existing = existingNodes.find(en => en.id === newNode.id);
                if (existing) {
                    return { ...existing, status: newNode.status, group: newNode.group };
                }
                return newNode;
            });

            // Update refs
            nodesRef.current = mergedNodes;
            linksRef.current = newLinks.map(l => ({ ...l }));

            // 4. Bind to D3
            const container = svg.select('g.container');
            const tooltip = d3.select("body").select(".d3-tooltip");

            const link = container.select("g.links")
                .selectAll("line")
                .data(linksRef.current)
                .join("line")
                .attr("stroke", "#ffffff20")
                .attr("stroke-opacity", 0.6)
                .attr("stroke-width", (d: any) => Math.sqrt(d.value));

            const node = container.select("g.nodes")
                .selectAll<SVGCircleElement, D3Node>("circle")
                .data(mergedNodes, (d: any) => d.id)
                .join(
                    enter => enter.append("circle")
                        .attr("r", (d: any) => d.group === 1 ? 14 : 8)
                        .attr("stroke", "#1e293b")
                        .attr("stroke-width", 1.5)
                        .call(d3.drag<SVGCircleElement, D3Node>()
                            .on("start", dragstarted)
                            .on("drag", dragged)
                            .on("end", dragended)),
                    update => update,
                    exit => exit.remove()
                )
                .attr("fill", (d: any) => {
                    if (d.status === 'error') return '#ef4444';
                    if (d.status === 'stopped') return '#64748b';
                    if (d.group === 1) return '#6366f1';
                    if (d.group === 3) return '#10b981';
                    if (d.group === 4) return '#f59e0b';
                    return '#3b82f6';
                })
                .style("transition", "fill 0.3s ease"); // Smooth status color changes

            node.on("mouseover", (event, d) => {
                tooltip.transition().duration(200).style("opacity", .9);
                tooltip.html(`<strong>${d.id}</strong><br/>Status: <span style="color: ${d.status === 'running' ? '#4ade80' : '#f87171'}">${d.status}</span>`)
                    .style("left", (event.pageX + 10) + "px")
                    .style("top", (event.pageY - 28) + "px");
                d3.select(event.currentTarget).attr("stroke", "#fff").attr("stroke-width", 3);
            })
            .on("mouseout", (event) => {
                tooltip.transition().duration(500).style("opacity", 0);
                d3.select(event.currentTarget).attr("stroke", "#1e293b").attr("stroke-width", 1.5);
            });

            const label = container.select("g.labels")
                .selectAll("text")
                .data(mergedNodes, (d: any) => d.id)
                .join("text")
                .text((d: any) => d.id)
                .attr('font-size', '10px')
                .attr('font-weight', 'bold')
                .attr('fill', '#94a3b8')
                .attr('dx', 15)
                .attr('dy', 4)
                .style('pointer-events', 'none');

            // Update simulation
            simulation.nodes(mergedNodes);
            simulation.force<d3.ForceLink<D3Node, D3Link>>("link")?.links(linksRef.current);
            
            // Re-heat simulation slightly to let it settle if new nodes added, 
            // but don't full reset if just updating status.
            if (mergedNodes.length !== existingNodes.length) {
                simulation.alpha(0.3).restart();
            }

            simulation.on("tick", () => {
                link
                    .attr("x1", (d: any) => (d.source as any).x)
                    .attr("y1", (d: any) => (d.source as any).y)
                    .attr("x2", (d: any) => (d.target as any).x)
                    .attr("y2", (d: any) => (d.target as any).y);

                node
                    .attr("cx", (d: any) => d.x!)
                    .attr("cy", (d: any) => d.y!);

                label
                    .attr("x", (d: any) => d.x!)
                    .attr("y", (d: any) => d.y!);
            });
        };

        updateGraph();

        function dragstarted(event: any) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }

        function dragged(event: any) {
            event.subject.fx = event.x;
            event.subject.fy = event.y;
        }

        function dragended(event: any) {
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
        }

    }, [metrics]);

    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 relative overflow-hidden backdrop-blur-xl h-full">
            <div className="flex items-center justify-between mb-4 relative z-10">
                <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                    <Network size={16} className="text-purple-400" /> App Topology Map
                </h2>
                <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Live Nodes</span>
            </div>
            <div className="w-full bg-slate-950/30 rounded-xl border border-white/5 overflow-hidden">
                <svg ref={svgRef} className="w-full cursor-grab active:cursor-grabbing" />
            </div>
        </div>
    );
}
