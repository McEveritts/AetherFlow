'use client';

import React, { useEffect, useRef } from 'react';
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

    useEffect(() => {
        if (!svgRef.current) return;
        
        // Clear previous SVG contents
        d3.select(svgRef.current).selectAll("*").remove();
        d3.select("body").selectAll(".d3-tooltip").remove();

        // 1. Prepare data
        const nodes: D3Node[] = [
            { id: 'AetherFlow Core', group: 1, status: 'running' }
        ];
        
        const links: D3Link[] = [];

        // Add services from metrics
        if (metrics.services) {
            Object.entries(metrics.services).forEach(([name, info]) => {
                nodes.push({ id: name, group: 2, status: info.status });
                links.push({ source: 'AetherFlow Core', target: name, value: 1 });
            });
        }
        
        // Add dummy nodes to simulate more complex topology requested by user
        nodes.push({ id: 'Proxy Port 8080', group: 3, status: 'running' });
        nodes.push({ id: 'Nginx Router', group: 3, status: 'running' });
        nodes.push({ id: 'PostgreSQL DB', group: 4, status: 'running' });
        nodes.push({ id: 'Redis Cache', group: 4, status: 'running' });

        links.push({ source: 'Proxy Port 8080', target: 'Nginx Router', value: 2 });
        links.push({ source: 'Nginx Router', target: 'AetherFlow Core', value: 2 });
        links.push({ source: 'AetherFlow Core', target: 'PostgreSQL DB', value: 2 });
        links.push({ source: 'AetherFlow Core', target: 'Redis Cache', value: 2 });

        const width = svgRef.current.parentElement?.clientWidth || 800;
        const height = 400;

        const svg = d3.select(svgRef.current)
            .attr('width', '100%')
            .attr('height', height)
            .attr('viewBox', [0, 0, width, height]);

        // Tooltip setup
        const tooltip = d3.select("body").append("div")
            .attr("class", "d3-tooltip absolute opacity-0 bg-slate-900 border border-white/10 p-2 rounded-lg text-xs text-white shadow-xl pointer-events-none z-[100] transition-opacity font-mono")

        const g = svg.append("g");

        const zoom = d3.zoom<SVGSVGElement, unknown>()
            .scaleExtent([0.5, 4])
            .on("zoom", (event) => {
                g.attr("transform", event.transform);
            });

        svg.call(zoom);

        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id((d: d3.SimulationNodeDatum) => (d as D3Node).id).distance(120))
            .force("charge", d3.forceManyBody().strength(-400))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collide", d3.forceCollide().radius(30));

        const link = g.append("g")
            .attr("stroke", "#ffffff20")
            .attr("stroke-opacity", 0.6)
            .selectAll("line")
            .data(links)
            .join("line")
            .attr("stroke-width", d => Math.sqrt(d.value));

        const node = g.append("g")
            .attr("stroke", "#fff")
            .attr("stroke-width", 1.5)
            .selectAll<SVGCircleElement, D3Node>("circle")
            .data(nodes)
            .join("circle")
            .attr("r", d => d.group === 1 ? 14 : 8)
            .attr("fill", d => {
                if (d.status === 'error') return '#ef4444';
                if (d.status === 'stopped') return '#64748b';
                if (d.group === 1) return '#6366f1';
                if (d.group === 3) return '#10b981';
                if (d.group === 4) return '#f59e0b';
                return '#3b82f6';
            })
            .attr("stroke", "#1e293b")
            .call(d3.drag<SVGCircleElement, D3Node>()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

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

        // Add labels
        const label = g.append("g")
            .selectAll("text")
            .data(nodes)
            .join("text")
            .text(d => d.id)
            .attr('font-size', '10px')
            .attr('font-weight', 'bold')
            .attr('fill', '#94a3b8')
            .attr('dx', 15)
            .attr('dy', 4)
            .style('pointer-events', 'none');

        simulation.on("tick", () => {
            link
                .attr("x1", d => (d.source as D3Node).x!)
                .attr("y1", d => (d.source as D3Node).y!)
                .attr("x2", d => (d.target as D3Node).x!)
                .attr("y2", d => (d.target as D3Node).y!);

            node
                .attr("cx", d => d.x!)
                .attr("cy", d => d.y!);

            label
                .attr("x", d => d.x!)
                .attr("y", d => d.y!);
        });

        function dragstarted(event: d3.D3DragEvent<SVGCircleElement, D3Node, D3Node>) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }

        function dragged(event: d3.D3DragEvent<SVGCircleElement, D3Node, D3Node>) {
            event.subject.fx = event.x;
            event.subject.fy = event.y;
        }

        function dragended(event: d3.D3DragEvent<SVGCircleElement, D3Node, D3Node>) {
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
        }
        
        return () => {
            simulation.stop();
            tooltip.remove();
        };
    }, [metrics]);

    return (
        <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 relative overflow-hidden backdrop-blur-xl">
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
