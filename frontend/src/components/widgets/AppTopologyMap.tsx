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
        if (viewMode !== 'graph' || !svgRef.current) {
            if (viewMode !== 'graph' && simulationRef.current) {
                simulationRef.current.on('tick', null);
                simulationRef.current.stop();
            }
            return;
        }

        const containerWidth = svgRef.current.parentElement?.clientWidth || 720;
        const containerHeight = isImmersive ? 380 : 300;
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
                .force('link', d3.forceLink<D3Node, D3Link>().id((nodeDatum) => (nodeDatum as D3Node).id).distance(isImmersive ? 110 : 80))
                .force('charge', d3.forceManyBody().strength(isImmersive ? -380 : -260))
                .force('center', d3.forceCenter(containerWidth / 2, containerHeight / 2))
                .force('collide', d3.forceCollide().radius(isImmersive ? 40 : 30));

            if (d3.select('body').select('.d3-topology-tooltip').empty()) {
                d3.select('body').append('div')
                    .attr('class', 'd3-topology-tooltip fixed opacity-0 bg-slate-900 border border-slate-700/80 p-2.5 rounded-xl text-xs text-white shadow-2xl pointer-events-none z-[100] font-mono');
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
        const mergedNodes = nextNodes.map(freshNode => {
            const existingNodeMatch = previousNodes.find(candidateNode => candidateNode.id === freshNode.id);
            if (existingNodeMatch) {
                return { ...existingNodeMatch, status: freshNode.status, group: freshNode.group, details: freshNode.details };
            }
            return freshNode;
        });

        nodesRef.current = mergedNodes;
        linksRef.current = nextLinks.map(linkItem => ({ ...linkItem }));

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
            .style('cursor', 'pointer');

        const displayTooltip = (mouseEvent: MouseEvent | TouchEvent, nodeDatum: D3Node) => {
            const pointerPageX = 'touches' in mouseEvent && mouseEvent.touches.length > 0 ? mouseEvent.touches[0].pageX : (mouseEvent as MouseEvent).pageX;
            const pointerPageY = 'touches' in mouseEvent && mouseEvent.touches.length > 0 ? mouseEvent.touches[0].pageY : (mouseEvent as MouseEvent).pageY;
            tooltipElement.transition().duration(120).style('opacity', 0.98);
            const statusTextColor = (nodeDatum.status === 'running' || nodeDatum.status === 'healthy') ? '#34d399' : (nodeDatum.status === 'stopped' ? '#94a3b8' : '#f87171');
            tooltipElement.html(`<div class="space-y-1"><div class="font-bold text-slate-100">${nodeDatum.id}</div><div class="text-xs text-slate-400">Status: <span style="color: ${statusTextColor}" class="font-semibold">${nodeDatum.status}</span></div></div>`)
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
            .text((nodeDatum) => nodeDatum.id)
            .attr('font-size', '11px')
            .attr('font-weight', '600')
            .attr('fill', '#e2e8f0')
            .attr('dx', 15)
            .attr('dy', 4)
            .style('pointer-events', 'none');

        simulation.nodes(mergedNodes);
        simulation.force<d3.ForceLink<D3Node, D3Link>>('link')?.links(linksRef.current);

        if (graphChanged || isNewGraphContainer) {
            simulation.alpha(0.3).restart();
        }

        const marginHorizontal = 80;
        const marginVertical = 20;

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

    }, [topologyData, isImmersive, realTopology, viewMode, canonicalCoreEntry]);

    useEffect(() => () => {
        if (simulationRef.current) {
            simulationRef.current.on('tick', null);
            simulationRef.current.stop();
        }
    }, []);

    return (
        <div className={`rounded-2xl border border-slate-800/80 bg-slate-900/85 backdrop-blur-xl relative overflow-hidden flex flex-col justify-between h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                <div className="flex flex-wrap items-center justify-between gap-3 pb-3 mb-3.5 border-b border-slate-800/80">
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
                        <div className="flex bg-slate-950/70 p-1 rounded-xl border border-slate-800" role="group" aria-label="Topology View Mode">
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
                        <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 rounded-xl bg-slate-950/60 border border-slate-800/70 text-xs text-slate-400">
                            <span className="font-medium text-slate-300">
                                Showing {isListExpanded ? `all ${totalManagedServicesCount}` : `${displayedCards.length} of ${totalManagedServicesCount}`} services
                            </span>
                            <div className="flex flex-wrap items-center gap-2 min-w-0 max-w-full">
                                {totalManagedServicesCount > PREVIEW_LIMIT && (
                                    <button
                                        type="button"
                                        onClick={() => setIsListExpanded(!isListExpanded)}
                                        className="min-h-[44px] px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs transition-colors flex items-center gap-1.5 focus-visible:ring-2 focus-visible:ring-indigo-500"
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

                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
                            {displayedCards.map(([serviceName, serviceInfo]) => {
                                const hasException = isServiceException(serviceInfo);
                                const isCore = isCoreService(serviceName);
                                if (hasException) {
                                    const exceptionDetail = getServiceExceptionDetail(serviceInfo);
                                    const isInstallFailure = serviceInfo.job_status === 'install_failed' || (serviceInfo.last_job?.action === 'install' && serviceInfo.last_job?.status !== 'completed');
                                    const badgeLabel = isInstallFailure ? 'Install Failed' : (serviceInfo.status === 'error' ? 'Failed' : 'Degraded');
                                    return (
                                        <div key={serviceName} className="bg-slate-950/70 border border-rose-500/40 rounded-xl p-3 flex flex-col justify-between">
                                            <div>
                                                <div className="space-y-1.5 mb-1">
                                                    <div className="text-sm font-bold text-slate-100 whitespace-normal break-words leading-tight">
                                                        {formatServiceName(serviceName)}
                                                    </div>
                                                    <div className="flex flex-wrap items-center gap-1.5">
                                                        {isCore && (
                                                            <span className="inline-flex items-center text-xs font-semibold px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                                                                Core
                                                            </span>
                                                        )}
                                                        <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">
                                                            <AlertTriangle size={11} className="text-rose-400" /> {badgeLabel}
                                                        </span>
                                                    </div>
                                                </div>
                                                <p className="text-xs text-rose-400 mt-1 font-medium whitespace-normal break-words" title={exceptionDetail}>
                                                    {exceptionDetail}
                                                </p>
                                            </div>
                                            <div className="flex items-center justify-between text-[13px] text-slate-300 mt-2 font-mono">
                                                {serviceInfo.version ? (
                                                    <span>v{serviceInfo.version}</span>
                                                ) : (
                                                    <span className="text-slate-500">--</span>
                                                )}
                                                <button
                                                    type="button"
                                                    onClick={() => setActiveTab('services')}
                                                    className="text-rose-400 hover:text-rose-200 focus-visible:ring-2 focus-visible:ring-rose-500 rounded p-1"
                                                    title={`Inspect ${serviceName}`}
                                                >
                                                    <ExternalLink size={13} />
                                                </button>
                                            </div>
                                        </div>
                                    );
                                }

                                if (serviceInfo.status === 'running') {
                                    return (
                                        <div key={serviceName} className={`bg-slate-950/60 rounded-xl p-3 flex flex-col justify-between ${isCore ? 'border border-indigo-500/30' : 'border border-slate-800/80'}`}>
                                            <div>
                                                <div className="space-y-1.5 mb-1">
                                                    <div className="text-sm font-bold text-slate-100 whitespace-normal break-words leading-tight">
                                                        {formatServiceName(serviceName)}
                                                    </div>
                                                    <div className="flex flex-wrap items-center gap-1.5">
                                                        {isCore && (
                                                            <span className="inline-flex items-center text-xs font-semibold px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                                                                Core
                                                            </span>
                                                        )}
                                                        <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                                                            <CheckCircle2 size={11} className="text-emerald-400" /> Running
                                                        </span>
                                                    </div>
                                                </div>
                                                <p className="text-xs text-slate-400 mt-1 whitespace-normal break-words">
                                                    {serviceInfo.uptime ? `Up ${serviceInfo.uptime}` : (isCore ? 'Core System Daemon' : 'Operational')}
                                                </p>
                                            </div>
                                            <div className="flex items-center justify-between text-[13px] text-slate-300 mt-2 font-mono">
                                                {serviceInfo.version ? (
                                                    <span>v{serviceInfo.version}</span>
                                                ) : (
                                                    <span className="text-slate-500">--</span>
                                                )}
                                                <button
                                                    type="button"
                                                    onClick={() => setActiveTab('services')}
                                                    className="text-slate-400 hover:text-slate-200 focus-visible:ring-2 focus-visible:ring-indigo-500 rounded p-1"
                                                    title={`Inspect ${serviceName}`}
                                                >
                                                    <ExternalLink size={13} />
                                                </button>
                                            </div>
                                        </div>
                                    );
                                }

                                return (
                                    <div key={serviceName} className="bg-slate-950/40 border border-slate-800/60 rounded-xl p-3 flex flex-col justify-between opacity-80">
                                        <div>
                                            <div className="space-y-1.5 mb-1">
                                                <div className="text-sm font-bold text-slate-200 whitespace-normal break-words leading-tight">
                                                    {formatServiceName(serviceName)}
                                                </div>
                                                <div className="flex flex-wrap items-center gap-1.5">
                                                    {isCore && (
                                                        <span className="inline-flex items-center text-xs font-semibold px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                                                            Core
                                                        </span>
                                                    )}
                                                    <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">
                                                        <PauseCircle size={11} /> Stopped
                                                    </span>
                                                </div>
                                            </div>
                                            <p className="text-xs text-slate-500 mt-1">{isCore ? 'Core System Daemon (Standby)' : 'Inactive daemon'}</p>
                                        </div>
                                        <div className="text-[13px] text-slate-300 mt-2 font-mono">
                                            {serviceInfo.version ? `v${serviceInfo.version} · Standby` : 'Standby (non-critical)'}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                        {displayedCards.length === 0 && (
                            <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800/60 text-xs text-slate-400 text-center">
                                No managed services registered.
                            </div>
                        )}
                    </div>
                ) : (
                    <div>
                        <div className="relative w-full bg-slate-950/60 rounded-xl border border-slate-800/60 overflow-hidden">
                            <div className="absolute top-2.5 right-2.5 z-20 flex items-center gap-1 bg-slate-900/90 border border-slate-800 rounded-lg p-1">
                                <button
                                    type="button"
                                    onClick={handleZoomIn}
                                    aria-label="Zoom in"
                                    className="min-h-[36px] min-w-[36px] flex items-center justify-center rounded text-slate-300 hover:text-white hover:bg-slate-800 transition-colors focus-visible:ring-2 focus-visible:ring-indigo-500"
                                >
                                    <ZoomIn size={16} />
                                </button>
                                <button
                                    type="button"
                                    onClick={handleZoomOut}
                                    aria-label="Zoom out"
                                    className="min-h-[36px] min-w-[36px] flex items-center justify-center rounded text-slate-300 hover:text-white hover:bg-slate-800 transition-colors focus-visible:ring-2 focus-visible:ring-indigo-500"
                                >
                                    <ZoomOut size={16} />
                                </button>
                                <button
                                    type="button"
                                    onClick={handleResetZoom}
                                    aria-label="Reset zoom"
                                    className="min-h-[36px] min-w-[36px] flex items-center justify-center rounded text-slate-300 hover:text-white hover:bg-slate-800 transition-colors focus-visible:ring-2 focus-visible:ring-indigo-500"
                                >
                                    <RotateCcw size={14} />
                                </button>
                            </div>
                            <svg ref={svgRef} className="w-full cursor-grab active:cursor-grabbing touch-none block" />
                        </div>
                        {selectedNodeId && (
                            <div className="mt-2.5 px-3 py-2 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs">
                                <div className="flex items-center gap-2">
                                    <span className="font-bold text-slate-200">{selectedNodeId}</span>
                                    <span className="text-slate-400">Node details active</span>
                                </div>
                                <button
                                    type="button"
                                    onClick={() => setSelectedNodeId(null)}
                                    className="text-slate-400 hover:text-slate-200 px-2 py-1 rounded text-xs focus-visible:ring-2 focus-visible:ring-indigo-500"
                                >
                                    Dismiss
                                </button>
                            </div>
                        )}
                    </div>
                )}
            </div>

            <div className="grid grid-cols-2 gap-2.5 mt-3.5">
                <div className="bg-slate-950/60 rounded-xl px-3.5 py-2.5 border border-slate-800/60 flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                        {viewMode === 'list' ? 'Registered Services' : 'Indexed Nodes'}
                    </span>
                    <span className="text-xs font-mono font-bold text-slate-200 tabular-nums">
                        {viewMode === 'list' ? `${totalManagedServicesCount} Services` : `${totalNodesCount} Nodes`}
                    </span>
                </div>
                <div className="bg-slate-950/60 rounded-xl px-3.5 py-2.5 border border-slate-800/60 flex items-center justify-between">
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
