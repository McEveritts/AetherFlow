import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as d3 from 'd3';
import { Network, ListFilter, AlertTriangle, CheckCircle2, PauseCircle, ExternalLink, ZoomIn, ZoomOut, RotateCcw, ChevronDown, ChevronUp } from 'lucide-react';
import useSWR from 'swr';
import { apiFetch } from '@/lib/fetcher';
import { SystemMetrics } from '@/types/dashboard';
import { useSystemStore } from '@/store/useSystemStore';
import { isServiceException, getServiceExceptionDetail, formatServiceName, isCoreService } from '@/components/widgets/serviceHealthHelpers';

interface AppTopologyMapProps {
    topologyData: SystemMetrics['services'];
    density?: 'compact' | 'immersive';
}

interface D3Node extends d3.SimulationNodeDatum {
    id: string;
    group: number;
    status: string;
    details?: string;
}

interface D3Link extends d3.SimulationLinkDatum<D3Node> {
    source: string | D3Node;
    target: string | D3Node;
    value: number;
}

export function computeTopologyLayout(nodeCount: number, width: number, minimumHeight: number) {
    const paddingX = 48;
    const paddingY = 32;
    const columns = Math.max(1, Math.floor((width - paddingX * 2) / 112) + 1);
    const rows = Math.max(1, Math.ceil(nodeCount / columns));
    const height = Math.max(minimumHeight, (rows - 1) * 112 + paddingY * 2);
    const positions = Array.from({ length: nodeCount }, (_, nodeIndex) => {
        const row = Math.floor(nodeIndex / columns);
        const nodesInRow = Math.min(columns, nodeCount - row * columns);
        return {
            x: nodesInRow === 1 ? width / 2 : paddingX + (nodeIndex % columns) * (width - paddingX * 2) / (nodesInRow - 1),
            y: rows === 1 ? height / 2 : paddingY + row * (height - paddingY * 2) / (rows - 1),
        };
    });
    return { height, positions, paddingX, paddingY };
}

export function formatTopologyLabel(name: string) {
    return name.length > 16 ? `${name.slice(0, 15)}…` : name;
}

export default function AppTopologyMap({ topologyData, density = 'compact' }: AppTopologyMapProps) {
    const isImmersive = density === 'immersive';
    const [viewMode, setViewMode] = useState<'list' | 'graph'>('list');
    const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
    const [isListExpanded, setIsListExpanded] = useState<boolean>(false);
    const setActiveTab = useSystemStore((state) => state.setActiveTab);

    const { data: realTopology } = useSWR<{
        nodes: { id: string; group: number; status: string; details?: string }[];
        links: { source: string; target: string; value: number }[];
    }>(
        '/api/v1/auth/system/topology',
        (targetUrl: string) => apiFetch(targetUrl).then(response => response.json()),
        { refreshInterval: 15000 }
    );

    const svgRef = useRef<SVGSVGElement>(null);
    const containerRef = useRef<HTMLDivElement>(null);
    const [containerSize, setContainerSize] = useState({ width: 720, height: 300 });
    const layoutSizeRef = useRef({ width: 0, height: 0 });
    const graphSvgRef = useRef<SVGSVGElement | null>(null);
    const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
    const simulationRef = useRef<d3.Simulation<D3Node, D3Link> | null>(null);
    const nodesRef = useRef<D3Node[]>([]);
    const linksRef = useRef<D3Link[]>([]);

    const serviceEntries = useMemo(() => Object.entries(topologyData || {}), [topologyData]);
    const canonicalCoreEntry = useMemo(() => {
        return serviceEntries.find(([serviceName]) => {
            const normalizedServiceName = serviceName.toLowerCase().replace(/[\s_-]+/g, '');
            return normalizedServiceName === 'aetherflowapi' || normalizedServiceName === 'aetherflow';
        });
    }, [serviceEntries]);

    const errorServices = useMemo(() => serviceEntries.filter(([, serviceInfo]) => isServiceException(serviceInfo)), [serviceEntries]);
    const stoppedServices = useMemo(() => serviceEntries.filter(([, serviceInfo]) => serviceInfo.status === 'stopped' && !isServiceException(serviceInfo)), [serviceEntries]);
    const activeServices = useMemo(() => {
        return serviceEntries.filter(([serviceName, serviceInfo]) => {
            if (isServiceException(serviceInfo)) return false;
            if (serviceInfo.status !== 'running') return false;
            if (isCoreService(serviceName)) return false;
            return true;
        });
    }, [serviceEntries]);
    const runningServicesCount = useMemo(() => serviceEntries.filter(([, serviceInfo]) => serviceInfo.status === 'running' && !isServiceException(serviceInfo)).length, [serviceEntries]);
    const totalManagedServicesCount = serviceEntries.length;
    const allPrioritizedServices = useMemo(() => {
        const errorList = [...errorServices];
        const coreList = serviceEntries.filter(([serviceName, serviceInfo]) =>
            isCoreService(serviceName) && !isServiceException(serviceInfo) && serviceInfo.status !== 'stopped'
        );
        const activeList = [...activeServices];
        const stoppedList = [...stoppedServices];
        const alreadyIncluded = new Set([
            ...errorList.map(([serviceName]) => serviceName),
            ...coreList.map(([serviceName]) => serviceName),
            ...activeList.map(([serviceName]) => serviceName),
            ...stoppedList.map(([serviceName]) => serviceName),
        ]);
        const remainingList = serviceEntries.filter(([serviceName]) => !alreadyIncluded.has(serviceName));
        return [...errorList, ...coreList, ...activeList, ...stoppedList, ...remainingList];
    }, [errorServices, serviceEntries, activeServices, stoppedServices]);

    const PREVIEW_LIMIT = 6;
    const displayedCards = isListExpanded ? allPrioritizedServices : allPrioritizedServices.slice(0, PREVIEW_LIMIT);
    const totalNodesCount = useMemo(() => {
        if (realTopology?.nodes && realTopology.nodes.length > 0) {
            const uniqueNodeKeys = new Set<string>();
            realTopology.nodes.forEach(remoteNode => {
                uniqueNodeKeys.add(remoteNode.id.toLowerCase().replace(/[\s_-]+/g, ''));
            });
            if (topologyData) {
                Object.keys(topologyData).forEach(serviceKey => {
                    uniqueNodeKeys.add(serviceKey.toLowerCase().replace(/[\s_-]+/g, ''));
                });
            }
            return uniqueNodeKeys.size;
        }
        return Math.max(1, serviceEntries.length + (canonicalCoreEntry ? 0 : 1));
    }, [realTopology, topologyData, serviceEntries, canonicalCoreEntry]);

    const handleZoomIn = () => {
        if (svgRef.current && zoomBehaviorRef.current) {
            d3.select(svgRef.current).transition().duration(250).call(zoomBehaviorRef.current.scaleBy, 1.3);
        }
    };

    const handleZoomOut = () => {
        if (svgRef.current && zoomBehaviorRef.current) {
            d3.select(svgRef.current).transition().duration(250).call(zoomBehaviorRef.current.scaleBy, 0.77);
        }
    };

    const handleResetZoom = () => {
        if (svgRef.current && zoomBehaviorRef.current) {
            d3.select(svgRef.current).transition().duration(300).call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
        }
    };

    useEffect(() => {
        if (viewMode !== 'graph' || !containerRef.current) return;
        const container = containerRef.current;
        const updateSize = (width = container.clientWidth, height = container.clientHeight) => {
            if (width <= 0) return;
            setContainerSize(previous => previous.width === width && previous.height === height
                ? previous
                : { width, height });
        };
        updateSize();
        if (typeof ResizeObserver === 'undefined') {
            const handleResize = () => updateSize();
            window.addEventListener('resize', handleResize);
            return () => window.removeEventListener('resize', handleResize);
        }
        const observer = new ResizeObserver(entries => {
            const entry = entries.find(candidate => candidate.target === container);
            if (entry) updateSize(entry.contentRect.width, entry.contentRect.height);
        });
        observer.observe(container);
        return () => observer.disconnect();
    }, [viewMode]);

    useEffect(() => {
        if (viewMode !== 'graph' || !svgRef.current) {
            if (viewMode !== 'graph' && simulationRef.current) {
                simulationRef.current.on('tick', null);
                simulationRef.current.stop();
            }
            return;
        }

        const containerWidth = containerSize.width;
        const layout = computeTopologyLayout(totalNodesCount, containerWidth, isImmersive ? 380 : 300);
        const containerHeight = layout.height;
        const dimensionsChanged = layoutSizeRef.current.width !== containerWidth || layoutSizeRef.current.height !== containerHeight;
        layoutSizeRef.current = { width: containerWidth, height: containerHeight };
        const isCoarseTouchDevice = typeof window !== 'undefined' && ((typeof window.matchMedia === 'function' && window.matchMedia('(pointer: coarse)').matches) || document.documentElement.dataset.touchMode === 'true');

        const svgSelection = d3.select(svgRef.current)
            .attr('width', '100%')
            .attr('height', containerHeight)
            .attr('viewBox', [0, 0, containerWidth, containerHeight]);

        let graphContainer = svgSelection.select<SVGGElement>('g.container');
        const isNewGraphContainer = graphSvgRef.current !== svgRef.current || graphContainer.empty();
        graphSvgRef.current = svgRef.current;
        if (isNewGraphContainer) {
            graphContainer = svgSelection.append('g').attr('class', 'container');
            graphContainer.append('g').attr('class', 'links');
            graphContainer.append('g').attr('class', 'nodes');
            graphContainer.append('g').attr('class', 'labels');

            const zoomBehavior = d3.zoom<SVGSVGElement, unknown>()
                .scaleExtent([0.5, 3.5])
                .on('zoom', (zoomEvent) => {
                    graphContainer.attr('transform', zoomEvent.transform);
                });

            zoomBehaviorRef.current = zoomBehavior;
            svgSelection.call(zoomBehavior);
        }

        if (!simulationRef.current) {
            simulationRef.current = d3.forceSimulation<D3Node, D3Link>()
                .force('link', d3.forceLink<D3Node, D3Link>().id((nodeDatum) => (nodeDatum as D3Node).id).distance(112).strength(0.04))
                .force('charge', d3.forceManyBody().strength(-80))
                .force('center', d3.forceCenter(containerWidth / 2, containerHeight / 2))
                .force('collide', d3.forceCollide().radius(52));

            if (d3.select('body').select('.d3-topology-tooltip').empty()) {
                d3.select('body').append('div')
                    .attr('class', 'd3-topology-tooltip fixed opacity-0 glass-panel border border-white/[0.08] backdrop-blur-xl p-2.5 rounded-xl text-xs text-white shadow-2xl pointer-events-none z-[100] font-mono');
            }
        } else {
            simulationRef.current.force('center', d3.forceCenter(containerWidth / 2, containerHeight / 2));
        }

        const simulation = simulationRef.current;

        const nextNodes: D3Node[] = [];
        const nextLinks: D3Link[] = [];

        const normalizeId = (rawId: string) => rawId.toLowerCase().replace(/[\s_-]+/g, '');

        const coreNodeIdentifier = canonicalCoreEntry
            ? canonicalCoreEntry[0]
            : (realTopology?.nodes?.find(remoteNode => remoteNode.group === 1)?.id || 'AetherFlow API');

        if (realTopology?.nodes && realTopology.nodes.length > 0) {
            realTopology.nodes.forEach(remoteNode => {
                const normalizedRemoteId = normalizeId(remoteNode.id);
                const isCoreCandidate = normalizedRemoteId === 'aetherflowapi' || normalizedRemoteId === 'aetherflow';
                const canonicalId = isCoreCandidate && canonicalCoreEntry ? canonicalCoreEntry[0] : remoteNode.id;
                const alreadyExists = nextNodes.some(existingNode => normalizeId(existingNode.id) === normalizedRemoteId);
                if (!alreadyExists) {
                    nextNodes.push({ id: canonicalId, group: remoteNode.group, status: remoteNode.status, details: remoteNode.details });
                }
            });
            if (realTopology.links) {
                realTopology.links.forEach(remoteLink => {
                    nextLinks.push({ source: remoteLink.source, target: remoteLink.target, value: remoteLink.value || 1 });
                });
            }
        } else {
            nextNodes.push({ id: coreNodeIdentifier, group: 1, status: 'running' });
        }

        if (topologyData) {
            Object.entries(topologyData).forEach(([serviceKey, serviceMetric]) => {
                const normalizedServiceKey = normalizeId(serviceKey);
                const isExistingNode = nextNodes.some(nodeItem => normalizeId(nodeItem.id) === normalizedServiceKey);
                if (!isExistingNode) {
                    const hasException = isServiceException(serviceMetric);
                    const computedStatus = hasException
                        ? (serviceMetric.job_status === 'install_failed' || (serviceMetric.last_job?.action === 'install' && serviceMetric.last_job?.status !== 'completed')
                            ? 'install_failed'
                            : (serviceMetric.status === 'error' ? 'error' : 'degraded'))
                        : serviceMetric.status;
                    nextNodes.push({ id: serviceKey, group: 4, status: computedStatus });
                    if (serviceKey !== coreNodeIdentifier) {
                        nextLinks.push({ source: coreNodeIdentifier, target: serviceKey, value: 1 });
                    }
                }
            });
        }

        const previousNodes = nodesRef.current;
        const nodeIds = (nodes: D3Node[]) => nodes.map(node => node.id).sort().join('\u0000');
        const linkIds = (links: D3Link[]) => links.map(link => {
            const source = typeof link.source === 'string' ? link.source : link.source.id;
            const target = typeof link.target === 'string' ? link.target : link.target.id;
            return JSON.stringify([source, target, link.value]);
        }).sort().join('\u0000');
        const graphChanged = nodeIds(previousNodes) !== nodeIds(nextNodes) || linkIds(linksRef.current) !== linkIds(nextLinks);
        const mergedNodes = nextNodes.map((freshNode, nodeIndex) => {
            const existingNodeMatch = previousNodes.find(candidateNode => candidateNode.id === freshNode.id);
            const position = layout.positions[nodeIndex];
            if (dimensionsChanged || graphChanged || isNewGraphContainer) {
                return { ...freshNode, ...position, vx: 0, vy: 0, fx: null, fy: null };
            }
            if (existingNodeMatch) {
                return { ...existingNodeMatch, status: freshNode.status, group: freshNode.group, details: freshNode.details };
            }
            return freshNode;
        });

        nodesRef.current = mergedNodes;
        linksRef.current = nextLinks.map(linkItem => ({ ...linkItem }));
        const targetPositions = new Map(mergedNodes.map((node, nodeIndex) => [node.id, layout.positions[nodeIndex]]));
        simulation
            .force('x', d3.forceX<D3Node>(node => targetPositions.get(node.id)?.x ?? containerWidth / 2).strength(0.6))
            .force('y', d3.forceY<D3Node>(node => targetPositions.get(node.id)?.y ?? containerHeight / 2).strength(0.6));
        if ((dimensionsChanged || isNewGraphContainer) && zoomBehaviorRef.current) {
            svgSelection.call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
        }

        const tooltipElement = d3.select('body').select<HTMLDivElement>('.d3-topology-tooltip');

        graphContainer.select('g.links')
            .selectAll<SVGLineElement, D3Link>('line')
            .data(linksRef.current)
            .join('line')
            .attr('stroke', '#64748b')
            .attr('stroke-opacity', 0.4)
            .attr('stroke-width', (linkDatum) => Math.sqrt(linkDatum.value || 1) * 1.5);

        const nodeSelection = graphContainer.select('g.nodes')
            .selectAll<SVGCircleElement, D3Node>('circle')
            .data(mergedNodes, (nodeDatum) => nodeDatum.id)
            .join(
                enterSelection => enterSelection.append('circle')
                    .attr('r', (nodeDatum) => nodeDatum.group === 1 ? (isCoarseTouchDevice ? 17 : 13) : (isCoarseTouchDevice ? 12 : 9))
                    .attr('stroke', '#0f172a')
                    .attr('stroke-width', 2)
                    .call(d3.drag<SVGCircleElement, D3Node>()
                        .on('start', onDragStart)
                        .on('drag', onDragProgress)
                        .on('end', onDragComplete)),
                updateSelection => updateSelection.attr('r', (nodeDatum) => nodeDatum.group === 1 ? (isCoarseTouchDevice ? 17 : 13) : (isCoarseTouchDevice ? 12 : 9)),
                exitSelection => exitSelection.remove()
            )
            .attr('fill', (nodeDatum) => {
                if (nodeDatum.status === 'error' || nodeDatum.status === 'failed' || nodeDatum.status === 'install_failed' || nodeDatum.status === 'degraded') return '#ef4444';
                if (nodeDatum.status === 'stopped') return '#64748b';
                if (nodeDatum.group === 1) return '#6366f1';
                if (nodeDatum.group === 3) return '#10b981';
                if (nodeDatum.group === 4) return '#06b6d4';
                return '#3b82f6';
            })
            .style('cursor', 'pointer')
            .attr('aria-label', nodeDatum => `${nodeDatum.id}: ${nodeDatum.status}`);
        nodeSelection.selectAll<SVGTitleElement, D3Node>('title')
            .data(nodeDatum => [nodeDatum])
            .join('title')
            .text(nodeDatum => nodeDatum.id);

        const displayTooltip = (mouseEvent: MouseEvent | TouchEvent, nodeDatum: D3Node) => {
            const pointerPageX = 'touches' in mouseEvent && mouseEvent.touches.length > 0 ? mouseEvent.touches[0].pageX : (mouseEvent as MouseEvent).pageX;
            const pointerPageY = 'touches' in mouseEvent && mouseEvent.touches.length > 0 ? mouseEvent.touches[0].pageY : (mouseEvent as MouseEvent).pageY;
            tooltipElement.transition().duration(120).style('opacity', 0.98);
            const statusTextColor = (nodeDatum.status === 'running' || nodeDatum.status === 'healthy') ? '#34d399' : (nodeDatum.status === 'stopped' ? '#94a3b8' : '#f87171');
            tooltipElement.text(`${nodeDatum.id} · ${nodeDatum.status}`)
                .style('color', statusTextColor)
                .style('left', `${pointerPageX + 12}px`)
                .style('top', `${pointerPageY - 32}px`);
            d3.select(mouseEvent.currentTarget as SVGCircleElement).attr('stroke', '#ffffff').attr('stroke-width', 3);
        };

        const hideTooltip = (mouseEvent: MouseEvent | TouchEvent) => {
            tooltipElement.transition().duration(250).style('opacity', 0);
            d3.select(mouseEvent.currentTarget as SVGCircleElement).attr('stroke', '#0f172a').attr('stroke-width', 2);
        };

        nodeSelection
            .on('mouseover', displayTooltip)
            .on('click', (mouseEvent, nodeDatum) => {
                displayTooltip(mouseEvent, nodeDatum);
                setSelectedNodeId(nodeDatum.id);
            })
            .on('mouseout', hideTooltip);

        const labelSelection = graphContainer.select('g.labels')
            .selectAll<SVGTextElement, D3Node>('text')
            .data(mergedNodes, (nodeDatum) => nodeDatum.id)
            .join('text')
            .text((nodeDatum) => formatTopologyLabel(nodeDatum.id))
            .attr('font-size', '12px')
            .attr('font-weight', '600')
            .attr('fill', '#e2e8f0')
            .attr('text-anchor', 'middle')
            .attr('dx', 0)
            .attr('dy', nodeDatum => nodeDatum.group === 1 ? 26 : 22)
            .attr('textLength', nodeDatum => Math.min(96, formatTopologyLabel(nodeDatum.id).length * 6))
            .attr('lengthAdjust', 'spacingAndGlyphs')
            .attr('aria-label', nodeDatum => nodeDatum.id)
            .style('pointer-events', 'none');

        simulation.nodes(mergedNodes);
        simulation.force<d3.ForceLink<D3Node, D3Link>>('link')?.links(linksRef.current);

        if (graphChanged || isNewGraphContainer || dimensionsChanged) {
            simulation.alpha(0.3).restart();
        }

        const marginHorizontal = layout.paddingX;
        const marginVertical = layout.paddingY;

        simulation.on('tick', () => {
            graphContainer.select('g.links')
                .selectAll<SVGLineElement, D3Link>('line')
                .attr('x1', (linkDatum) => {
                    const sourceNode = linkDatum.source as unknown as D3Node;
                    return Math.max(marginHorizontal, Math.min(containerWidth - marginHorizontal, sourceNode.x ?? containerWidth / 2));
                })
                .attr('y1', (linkDatum) => {
                    const sourceNode = linkDatum.source as unknown as D3Node;
                    return Math.max(marginVertical, Math.min(containerHeight - marginVertical, sourceNode.y ?? containerHeight / 2));
                })
                .attr('x2', (linkDatum) => {
                    const targetNode = linkDatum.target as unknown as D3Node;
                    return Math.max(marginHorizontal, Math.min(containerWidth - marginHorizontal, targetNode.x ?? containerWidth / 2));
                })
                .attr('y2', (linkDatum) => {
                    const targetNode = linkDatum.target as unknown as D3Node;
                    return Math.max(marginVertical, Math.min(containerHeight - marginVertical, targetNode.y ?? containerHeight / 2));
                });

            nodeSelection
                .attr('cx', (nodeDatum) => {
                    const boundedPositionX = Math.max(marginHorizontal, Math.min(containerWidth - marginHorizontal, nodeDatum.x ?? containerWidth / 2));
                    nodeDatum.x = boundedPositionX;
                    return boundedPositionX;
                })
                .attr('cy', (nodeDatum) => {
                    const boundedPositionY = Math.max(marginVertical, Math.min(containerHeight - marginVertical, nodeDatum.y ?? containerHeight / 2));
                    nodeDatum.y = boundedPositionY;
                    return boundedPositionY;
                });

            labelSelection
                .attr('x', (nodeDatum) => nodeDatum.x ?? containerWidth / 2)
                .attr('y', (nodeDatum) => nodeDatum.y ?? containerHeight / 2);
        });

        function onDragStart(dragEvent: d3.D3DragEvent<SVGCircleElement, D3Node, D3Node>) {
            if (!dragEvent.active) simulation.alphaTarget(0.3).restart();
            dragEvent.subject.fx = dragEvent.subject.x;
            dragEvent.subject.fy = dragEvent.subject.y;
        }

        function onDragProgress(dragEvent: d3.D3DragEvent<SVGCircleElement, D3Node, D3Node>) {
            dragEvent.subject.fx = dragEvent.x;
            dragEvent.subject.fy = dragEvent.y;
        }

        function onDragComplete(dragEvent: d3.D3DragEvent<SVGCircleElement, D3Node, D3Node>) {
            if (!dragEvent.active) simulation.alphaTarget(0);
            dragEvent.subject.fx = null;
            dragEvent.subject.fy = null;
        }

    }, [topologyData, isImmersive, realTopology, viewMode, canonicalCoreEntry, containerSize, totalNodesCount]);

    useEffect(() => () => {
        if (simulationRef.current) {
            simulationRef.current.on('tick', null);
            simulationRef.current.stop();
        }
    }, []);

    return (
        <div className={`obs-telemetry-surface relative overflow-hidden flex flex-col justify-between h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                <div className="flex flex-wrap items-center justify-between gap-3 pb-3 mb-3.5 border-b border-white/[0.06]">
                    <div className="flex items-center gap-2.5">
                        <div className="h-8 w-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 shrink-0">
                            <Network size={16} />
                        </div>
                        <div>
                            <h2 className="text-sm font-bold text-slate-100 tracking-tight leading-none">
                                {viewMode === 'list' ? 'Service Health' : 'Service Topology Mesh'}
                            </h2>
                            <p className="text-xs text-slate-400 mt-1">
                                {viewMode === 'list' ? 'Managed service status and daemon health' : 'Interconnect health and daemon registry'}
                            </p>
                        </div>
                    </div>

                    <div className="flex items-center gap-2">
                        <div className="flex flex-wrap bg-white/[0.03] p-1 rounded-xl border border-white/[0.08] backdrop-blur-md" role="group" aria-label="Topology View Mode">
                            <button
                                type="button"
                                onClick={() => setViewMode('list')}
                                aria-label="Show scannable service health list"
                                className={`min-h-[40px] px-3.5 py-2 text-xs font-semibold rounded-lg transition-all flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none ${
                                    viewMode === 'list'
                                        ? 'bg-indigo-600/30 text-indigo-200 border border-indigo-500/50 shadow-sm'
                                        : 'text-slate-400 hover:text-slate-200'
                                }`}
                            >
                                <ListFilter size={14} />
                                <span>Health List</span>
                            </button>
                            <button
                                type="button"
                                onClick={() => setViewMode('graph')}
                                aria-label="Show interactive topology graph"
                                className={`min-h-[40px] px-3.5 py-2 text-xs font-semibold rounded-lg transition-all flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:outline-none ${
                                    viewMode === 'graph'
                                        ? 'bg-indigo-600/30 text-indigo-200 border border-indigo-500/50 shadow-sm'
                                        : 'text-slate-400 hover:text-slate-200'
                                }`}
                            >
                                <Network size={14} />
                                <span>Topology Graph</span>
                            </button>
                        </div>
                    </div>
                </div>

                {viewMode === 'list' ? (
                    <div className="space-y-3">
                        <div className="flex flex-wrap items-center justify-between gap-2 pb-2 text-xs text-slate-400">
                            <span className="font-medium text-slate-300">
                                Showing {isListExpanded ? `all ${totalManagedServicesCount}` : `${displayedCards.length} of ${totalManagedServicesCount}`} services
                            </span>
                            <div className="flex flex-wrap items-center gap-2 min-w-0 max-w-full">
                                {totalManagedServicesCount > PREVIEW_LIMIT && (
                                    <button
                                        type="button"
                                        onClick={() => setIsListExpanded(!isListExpanded)}
                                        className="min-h-[44px] px-3.5 py-2 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] text-slate-200 font-semibold text-xs transition-colors flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-indigo-500"
                                        aria-label={isListExpanded ? 'Collapse service list to preview' : 'Expand service list to show all services'}
                                    >
                                        {isListExpanded ? (
                                            <>
                                                <span>Collapse</span>
                                                <ChevronUp size={14} className="text-slate-400" />
                                            </>
                                        ) : (
                                            <>
                                                <span>Expand All ({totalManagedServicesCount})</span>
                                                <ChevronDown size={14} className="text-slate-400" />
                                            </>
                                        )}
                                    </button>
                                )}
                                <button
                                    type="button"
                                    onClick={() => setActiveTab('services')}
                                    className="min-h-[44px] px-3.5 py-2 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 font-semibold text-xs transition-colors flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-indigo-500"
                                    aria-label="View in Services"
                                >
                                    <span>View in Services</span>
                                    <ExternalLink size={13} />
                                </button>
                            </div>
                        </div>

                        <div role="list" aria-label="Managed service health" className="divide-y divide-white/[0.06]">
                            {displayedCards.map(([serviceName, serviceInfo]) => {
                                const hasException = isServiceException(serviceInfo);
                                const isCore = isCoreService(serviceName);
                                const isRunning = serviceInfo.status === 'running';
                                const isInstallFailure = serviceInfo.job_status === 'install_failed' || (serviceInfo.last_job?.action === 'install' && serviceInfo.last_job?.status !== 'completed');
                                const statusLabel = hasException
                                    ? (isInstallFailure ? 'Install Failed' : serviceInfo.status === 'error' ? 'Failed' : 'Degraded')
                                    : isRunning ? 'Running' : 'Stopped';
                                const exceptionDetail = hasException ? getServiceExceptionDetail(serviceInfo) : '';
                                const detail = hasException
                                    ? exceptionDetail
                                    : isRunning
                                        ? (serviceInfo.uptime ? `Up ${serviceInfo.uptime}` : isCore ? 'Core System Daemon' : 'Operational')
                                        : isCore ? 'Core System Daemon (Standby)' : 'Inactive daemon';

                                return (
                                    <div key={serviceName} role="listitem" className="flex items-start gap-3 py-3 first:pt-0 last:pb-0 min-w-0">
                                        <span aria-hidden="true" className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${
                                            hasException ? 'bg-rose-400 shadow-[0_0_8px_rgba(244,63,94,0.4)]' : isRunning ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.3)]' : 'bg-slate-500'
                                        }`} />
                                        <div className="flex-1 min-w-0">
                                            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                                                <div className="text-sm font-semibold text-slate-100 whitespace-normal break-words leading-tight">
                                                    {formatServiceName(serviceName)}
                                                </div>
                                                {isCore && <span className="text-xs font-medium text-indigo-300">Core</span>}
                                                <span className={`inline-flex items-center gap-1 text-xs font-medium ${
                                                    hasException ? 'text-rose-300' : isRunning ? 'text-emerald-300' : 'text-slate-400'
                                                }`}>
                                                    {hasException ? <AlertTriangle size={11} /> : isRunning ? <CheckCircle2 size={11} /> : <PauseCircle size={11} />}
                                                    {statusLabel}
                                                </span>
                                            </div>
                                            <p className={`text-xs mt-1 whitespace-normal break-words ${hasException ? 'text-rose-300/80' : 'text-slate-400'}`} title={exceptionDetail || undefined}>
                                                {detail}
                                            </p>
                                        </div>
                                        <div className="flex shrink-0 items-center gap-1 text-xs font-mono text-slate-400">
                                            <span className="max-w-[7rem] break-words text-right">
                                                {!hasException && !isRunning
                                                    ? (serviceInfo.version ? `v${serviceInfo.version} · Standby` : 'Standby (non-critical)')
                                                    : serviceInfo.version ? `v${serviceInfo.version}` : '--'}
                                            </span>
                                            <button
                                                type="button"
                                                onClick={() => setActiveTab('services')}
                                                aria-label={`Inspect ${serviceName}`}
                                                title={`Inspect ${serviceName}`}
                                                className={`min-h-[40px] min-w-[40px] flex items-center justify-center rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 ${hasException ? 'text-rose-400 hover:text-rose-200' : 'text-slate-400 hover:text-slate-200'}`}
                                            >
                                                <ExternalLink size={13} />
                                            </button>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                        {displayedCards.length === 0 && (
                            <div className="py-6 text-xs text-slate-400 text-center">
                                No managed services registered.
                            </div>
                        )}
                    </div>
                ) : (
                    <div>
                        <div ref={containerRef} className="relative w-full min-w-0 max-h-[420px] overflow-y-auto obs-scroller">
                            <div className="sticky top-0 z-20 flex justify-end items-center gap-1 glass-panel backdrop-blur-xl border border-white/[0.08] rounded-lg p-1 w-fit ml-auto mb-2">
                                <button
                                    type="button"
                                    onClick={handleZoomIn}
                                    aria-label="Zoom in"
                                    className="min-h-[40px] min-w-[40px] obs-touch-target-standard flex items-center justify-center rounded text-slate-300 hover:text-white hover:bg-white/[0.06] transition-colors focus-visible:ring-2 focus-visible:ring-indigo-500"
                                >
                                    <ZoomIn size={16} />
                                </button>
                                <button
                                    type="button"
                                    onClick={handleZoomOut}
                                    aria-label="Zoom out"
                                    className="min-h-[40px] min-w-[40px] obs-touch-target-standard flex items-center justify-center rounded text-slate-300 hover:text-white hover:bg-white/[0.06] transition-colors focus-visible:ring-2 focus-visible:ring-indigo-500"
                                >
                                    <ZoomOut size={16} />
                                </button>
                                <button
                                    type="button"
                                    onClick={handleResetZoom}
                                    aria-label="Reset zoom"
                                    className="min-h-[40px] min-w-[40px] obs-touch-target-standard flex items-center justify-center rounded text-slate-300 hover:text-white hover:bg-white/[0.06] transition-colors focus-visible:ring-2 focus-visible:ring-indigo-500"
                                >
                                    <RotateCcw size={14} />
                                </button>
                            </div>
                            <svg ref={svgRef} className="w-full cursor-grab active:cursor-grabbing touch-none block" />
                        </div>
                        {selectedNodeId && (
                            <div className="mt-2.5 py-2 border-t border-white/[0.06] flex items-center justify-between text-xs">
                                <div className="flex items-center gap-2">
                                    <span className="font-bold text-slate-200">{selectedNodeId}</span>
                                    <span className="text-slate-400">Node details active</span>
                                </div>
                                <button
                                    type="button"
                                    onClick={() => setSelectedNodeId(null)}
                                    className="min-h-[40px] obs-touch-target-standard text-slate-400 hover:text-slate-200 px-2 py-1 rounded text-xs focus-visible:ring-2 focus-visible:ring-indigo-500"
                                >
                                    Dismiss
                                </button>
                            </div>
                        )}
                    </div>
                )}
            </div>

            <div className="grid grid-cols-2 gap-0 mt-3.5 pt-3 border-t border-white/[0.06] divide-x divide-white/[0.06]">
                <div className="min-w-0 flex flex-wrap items-baseline justify-between gap-x-2 gap-y-1 pr-3 last:pr-0 last:pl-3">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                        {viewMode === 'list' ? 'Registered Services' : 'Indexed Nodes'}
                    </span>
                    <span className="text-xs font-mono font-bold text-slate-200 tabular-nums">
                        {viewMode === 'list' ? `${totalManagedServicesCount} Services` : `${totalNodesCount} Nodes`}
                    </span>
                </div>
                <div className="min-w-0 flex flex-wrap items-baseline justify-between gap-x-2 gap-y-1 pr-3 last:pr-0 last:pl-3">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                        {viewMode === 'list' ? 'Healthy Services' : 'Healthy Daemons'}
                    </span>
                    <span className="text-xs font-mono font-bold text-emerald-400 tabular-nums">
                        {viewMode === 'list'
                            ? `${runningServicesCount} / ${totalManagedServicesCount} Online`
                            : `${runningServicesCount} / ${serviceEntries.length || runningServicesCount} Online`}
                    </span>
                </div>
            </div>
        </div>
    );
}
