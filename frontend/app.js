const { createApp, computed, nextTick, onMounted, ref } = Vue;

const API_URL = "/api/topology";
const LOCAL_API_URL = "http://127.0.0.1:8000/api/topology";

const TAG_GROUPS = {
    risk: ["Adult", "Gambling", "Phishing", "Malware"],
    infra: ["CDN", "WAF", "DNS", "Hosting", "CloudService", "StaticSite", "API"],
    tech: ["TechPlatform", "Security", "Academic"],
    business: ["Corporate", "Ecommerce", "Finance", "BusinessService", "ConsumerService", "Education", "Government"],
    content: ["News", "Social"],
};

const EDGE_OPTIONS = [
    { key: "ssl", label: "同证书" },
    { key: "fingerprint", label: "同指纹" },
    { key: "asn", label: "同 ASN/服务商" },
    { key: "domain", label: "同主域/品牌" },
    { key: "link", label: "链接引用" },
];

createApp({
    setup() {
        const nodes = ref([]);
        const edges = ref([]);
        const globalStats = ref({ total_nodes: 0, total_edges: 0, risk_nodes: 0, infra_nodes: 0 });
        const searchText = ref("");
        const selectedTag = ref("");
        const selectedNode = ref(null);
        const isLoading = ref(false);
        const isProbing = ref(false);
        const loadError = ref("");
        const isSearchMode = ref(false);
        const mapReady = ref(false);
        const mapMode = ref("globe");
        const detailPanelOpen = ref(false);
        const detailTarget = ref(null);
        const starMapOpen = ref(false);
        const graphSelection = ref(null);
        const edgeFilters = ref({ ssl: true, fingerprint: true, asn: true, domain: true, link: true });

        let map = null;
        let globe = null;
        let network = null;
        let graphNodesData = null;
        let graphEdgesData = null;
        let nodeLayer = null;
        let edgeLayer = null;
        let tileFallbackActive = false;
        let decorators = [];
        const markerById = new Map();

        const edgeOptions = EDGE_OPTIONS;

        const visibleNodes = computed(() => {
            if (!selectedTag.value) return nodes.value;
            return nodes.value.filter((node) => nodeTags(node).includes(selectedTag.value));
        });

        const tagCounts = computed(() => {
            const counts = {};
            nodes.value.forEach((node) => {
                nodeTags(node).forEach((tag) => {
                    counts[tag] = (counts[tag] || 0) + 1;
                });
            });
            return counts;
        });

        const topTags = computed(() => {
            return Object.entries(tagCounts.value)
                .map(([name, count]) => ({ name, count }))
                .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
                .slice(0, 18);
        });

        const leadingTag = computed(() => topTags.value[0]?.name || "");
        const riskCount = computed(() => nodes.value.filter((node) => nodeTags(node).some(isRiskTag)).length);
        const infraCount = computed(() => nodes.value.filter((node) => nodeTags(node).some(isInfraTag)).length);
        const metricLabels = computed(() => isSearchMode.value
            ? { nodes: "相关节点", edges: "相关关系", risk: "相关风险", infra: "相关基础设施" }
            : { nodes: "全站节点", edges: "全站关系", risk: "风险节点", infra: "基础设施" }
        );
        const metricStats = computed(() => {
            if (isSearchMode.value) {
                return {
                    total_nodes: nodes.value.length,
                    total_edges: edges.value.length,
                    risk_nodes: riskCount.value,
                    infra_nodes: infraCount.value,
                };
            }
            return globalStats.value;
        });
        const pageTitle = computed(() => isSearchMode.value ? "目标关联拓扑" : "全局资产态势");
        const modeLabel = computed(() => isSearchMode.value ? "Search Focus" : "Overview Sample");

        function nodeTags(node) {
            return (node.tags || []).map((tag) => tag.name).filter(Boolean);
        }

        function isRiskTag(tag) {
            return TAG_GROUPS.risk.includes(tag);
        }

        function isInfraTag(tag) {
            return TAG_GROUPS.infra.includes(tag);
        }

        function tagClass(tag) {
            if (TAG_GROUPS.risk.includes(tag)) return "tag-risk";
            if (TAG_GROUPS.infra.includes(tag)) return "tag-infra";
            if (TAG_GROUPS.tech.includes(tag)) return "tag-tech";
            if (TAG_GROUPS.business.includes(tag)) return "tag-business";
            if (TAG_GROUPS.content.includes(tag)) return "tag-content";
            return "tag-neutral";
        }

        function nodeTone(node) {
            const tags = nodeTags(node);
            const mainTag = primaryTag(node);
            if (tags.some(isRiskTag) || node.type === "scam") return "risk";
            if (TAG_GROUPS.infra.includes(mainTag) || node.type === "cdn") return "infra";
            if (TAG_GROUPS.tech.includes(mainTag)) return "tech";
            if (TAG_GROUPS.business.includes(mainTag)) return "business";
            if (TAG_GROUPS.content.includes(mainTag)) return "content";
            return "normal";
        }

        function primaryTag(node) {
            const tags = nodeTags(node);
            return tags[0] || "Unknown";
        }

        function tagPercent(count) {
            const max = topTags.value[0]?.count || 1;
            return Math.max(6, Math.round((count / max) * 100));
        }

        function modelConfidences(node) {
            const confs = node?.details?.model_confidences || {};
            return Object.entries(confs)
                .map(([name, value]) => ({ name, value: Number(value) || 0 }))
                .filter((item) => item.value > 0.05)
                .sort((a, b) => b.value - a.value)
                .slice(0, 6);
        }

        function detailValue(key) {
            const value = selectedNode.value?.details?.[key];
            if (value === undefined || value === null || value === "" || value === "N/A") return "暂无";
            if (Array.isArray(value)) return value.join(", ");
            if (typeof value === "object") return JSON.stringify(value);
            return String(value);
        }

        function nodeDetailValue(node, key) {
            const value = node?.details?.[key];
            if (value === undefined || value === null || value === "" || value === "N/A") return "暂无";
            if (Array.isArray(value)) return value.join(", ");
            if (typeof value === "object") return JSON.stringify(value);
            return String(value);
        }

        function splitList(value) {
            if (!value || value === "暂无" || value === "鏆傛棤") return [];
            return String(value)
                .split(/[,;|，、\s]+/)
                .map((item) => item.trim())
                .filter((item) => item && !["N/A", "Unknown", "None", "Timeout"].includes(item));
        }

        function coordinateText(node) {
            if (!validCoord(node)) return "暂无有效坐标";
            return `${Number(node.lat).toFixed(4)}, ${Number(node.lng).toFixed(4)}`;
        }

        function faviconUrl(node) {
            const domain = node?.domain || "";
            return domain ? `https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=96` : "";
        }

        function handleFaviconError(event) {
            event.target.style.display = "none";
        }

        async function fetchTopology(keyword = "") {
            isLoading.value = true;
            try {
                const suffix = keyword ? `?keyword=${encodeURIComponent(keyword)}` : "";
                const data = await requestTopology(suffix);
                loadError.value = "";
                isProbing.value = data.status === "probing";
                nodes.value = data.nodes || [];
                edges.value = data.edges || [];
                globalStats.value = data.stats || {
                    total_nodes: nodes.value.length,
                    total_edges: edges.value.length,
                    risk_nodes: riskCount.value,
                    infra_nodes: infraCount.value,
                };
                isSearchMode.value = Boolean(keyword);
                selectedNode.value = keyword ? findBestMatch(keyword) : null;
                await nextTick();
                renderMap();
                renderGlobe();
                if (keyword && selectedNode.value) {
                    setTimeout(() => focusTargetNode(selectedNode.value), 180);
                }
            } catch (error) {
                console.error("Topology request failed", error);
                loadError.value = "后端连接失败，请先启动 API 服务";
            } finally {
                isLoading.value = false;
            }
        }

        async function requestTopology(suffix) {
            const candidates = [];
            if (window.location.protocol !== "file:") {
                candidates.push(`${API_URL}${suffix}`);
            }
            candidates.push(`${LOCAL_API_URL}${suffix}`);

            let lastError = null;
            for (const url of [...new Set(candidates)]) {
                try {
                    const response = await fetch(url);
                    if (!response.ok) throw new Error(`HTTP ${response.status}`);
                    return await response.json();
                } catch (error) {
                    lastError = error;
                }
            }
            throw lastError || new Error("Topology request failed");
        }

        function findBestMatch(keyword) {
            const k = keyword.toLowerCase();
            const exact = nodes.value.find((node) =>
                String(node.domain || "").toLowerCase() === k ||
                String(node.ip || "").toLowerCase() === k
            );
            if (exact) return exact;
            return nodes.value.find((node) =>
                String(node.domain || "").toLowerCase().includes(k) ||
                String(node.ip || "").toLowerCase().includes(k)
            ) || nodes.value[0] || null;
        }

        function runSearch() {
            const keyword = searchText.value.trim();
            if (!keyword) return reloadOverview();
            fetchTopology(keyword);
        }

        function reloadOverview() {
            searchText.value = "";
            selectedTag.value = "";
            fetchTopology("");
        }

        function resetWorkspace() {
            selectedNode.value = null;
            reloadOverview();
        }

        function toggleTag(tag) {
            selectedTag.value = selectedTag.value === tag ? "" : tag;
            renderMap();
            renderGlobe();
        }

        function clearTagFilter() {
            selectedTag.value = "";
            renderMap();
            renderGlobe();
        }

        function initMap() {
            if (map) return;
            map = L.map("leaflet-container", {
                zoomControl: false,
                attributionControl: false,
                minZoom: 2,
                maxBounds: [[-85, -180], [85, 180]],
            }).setView([22, 18], 3);

            L.control.zoom({ position: "bottomright" }).addTo(map);
            const primaryTiles = L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
                subdomains: "abcd",
                maxZoom: 19,
            });

            primaryTiles.on("tileerror", () => {
                if (tileFallbackActive || !map) return;
                tileFallbackActive = true;
                primaryTiles.setOpacity(0);
                L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
                    maxZoom: 19,
                    opacity: 0.7,
                }).addTo(map);
            });

            primaryTiles.addTo(map);

            edgeLayer = L.layerGroup().addTo(map);
            nodeLayer = L.layerGroup().addTo(map);
            mapReady.value = true;
            refreshLeafletSize();
            window.addEventListener("resize", refreshLeafletSize);
        }

        function initGlobe() {
            if (globe || !window.Globe) return;
            const container = document.getElementById("globe-container");
            if (!container) return;
            globe = window.Globe()(container)
                .globeImageUrl("https://unpkg.com/three-globe/example/img/earth-night.jpg")
                .bumpImageUrl("https://unpkg.com/three-globe/example/img/earth-topology.png")
                .backgroundColor("rgba(0,0,0,0)")
                .showAtmosphere(true)
                .atmosphereColor("#22d3ee")
                .atmosphereAltitude(0.18)
                .pointAltitude((point) => point.active ? 0.035 : 0.018)
                .pointRadius((point) => point.active ? 0.72 : 0.42)
                .pointColor((point) => point.color)
                .arcColor((arc) => arc.color)
                .arcAltitudeAutoScale(0.35)
                .arcStroke(0.5)
                .arcDashLength(0.34)
                .arcDashGap(1.8)
                .arcDashAnimateTime(2600)
                .onPointClick((point) => selectNode(point.node, true));

            resizeGlobe();
            window.addEventListener("resize", resizeGlobe);
        }

        function resizeGlobe() {
            const container = document.getElementById("globe-container");
            if (globe && container) {
                globe.width(container.clientWidth).height(container.clientHeight);
            }
        }

        function refreshLeafletSize() {
            if (!map) return;
            map.invalidateSize({ animate: false, pan: false });
            requestAnimationFrame(() => {
                map.invalidateSize({ animate: false, pan: false });
                requestAnimationFrame(() => {
                    map.invalidateSize({ animate: false, pan: false });
                });
            });
        }

        function markerColor(node) {
            const tone = nodeTone(node);
            if (tone === "risk") return "#ef4444";
            if (tone === "infra") return "#22c55e";
            if (tone === "tech") return "#8b5cf6";
            if (tone === "business") return "#f59e0b";
            if (tone === "content") return "#38bdf8";
            return "#06b6d4";
        }

        function renderMap() {
            if (!map) return;
            nodeLayer.clearLayers();
            edgeLayer.clearLayers();
            decorators.forEach((item) => map.removeLayer(item));
            decorators = [];
            markerById.clear();

            const activeNodes = visibleNodes.value.filter((node) => validCoord(node));
            const activeIds = new Set(activeNodes.map((node) => node.id));
            const byId = Object.fromEntries(nodes.value.map((node) => [node.id, node]));

            edges.value.forEach((edge) => {
                const edgeType = normalizeEdgeType(edge.type);
                if (!edgeFilters.value[edgeType]) return;
                if (!activeIds.has(edge.from) || !activeIds.has(edge.to)) return;
                const from = byId[edge.from];
                const to = byId[edge.to];
                if (!validCoord(from) || !validCoord(to)) return;
                const options = edgeStyle(edgeType);
                const line = L.polyline([[from.lat, from.lng], [to.lat, to.lng]], options).addTo(edgeLayer);
                line.bindTooltip(edgeTooltip(edge, edgeType), { className: "map-tooltip", sticky: true });
                if (edgeType === "link" && window.L.polylineDecorator) {
                    const deco = L.polylineDecorator(line, {
                        patterns: [{
                            offset: "55%",
                            repeat: 0,
                            symbol: L.Symbol.arrowHead({
                                pixelSize: 10,
                                polygon: false,
                                pathOptions: { stroke: true, color: "#f59e0b", weight: 2 },
                            }),
                        }],
                    }).addTo(map);
                    decorators.push(deco);
                }
            });

            activeNodes.forEach((node) => {
                const marker = L.marker([node.lat, node.lng], {
                    icon: nodeIcon(node, selectedNode.value?.id === node.id),
                    riseOnHover: true,
                }).addTo(nodeLayer);
                marker.bindTooltip(markerTooltip(node), { direction: "top", offset: [0, -16], className: "map-tooltip" });
                marker.on("click", () => selectNode(node, false));
                markerById.set(node.id, marker);
            });

            if (selectedNode.value && markerById.has(selectedNode.value.id)) {
                markerById.get(selectedNode.value.id).openTooltip();
            }
        }

        function renderGlobe() {
            if (!globe) return;
            const activeNodes = visibleNodes.value.filter(validCoord);
            const activeIds = new Set(activeNodes.map((node) => node.id));
            const byId = Object.fromEntries(nodes.value.map((node) => [node.id, node]));

            const points = activeNodes.map((node) => ({
                lat: Number(node.lat),
                lng: Number(node.lng),
                color: markerColor(node),
                active: selectedNode.value?.id === node.id,
                node,
            }));

            const arcs = edges.value
                .filter((edge) => edgeFilters.value[normalizeEdgeType(edge.type)])
                .filter((edge) => activeIds.has(edge.from) && activeIds.has(edge.to))
                .map((edge) => {
                    const from = byId[edge.from];
                    const to = byId[edge.to];
                    if (!validCoord(from) || !validCoord(to)) return null;
                    const edgeType = normalizeEdgeType(edge.type);
                    return {
                        startLat: Number(from.lat),
                        startLng: Number(from.lng),
                        endLat: Number(to.lat),
                        endLng: Number(to.lng),
                        color: [edgeColor(edgeType), edgeColor(edgeType)],
                    };
                })
                .filter(Boolean);

            globe.pointsData(points).arcsData(arcs);
        }

        function validCoord(node) {
            return node && Number.isFinite(Number(node.lat)) && Number.isFinite(Number(node.lng)) &&
                (Number(node.lat) !== 0 || Number(node.lng) !== 0);
        }

        function nodeIcon(node, active = false) {
            const color = markerColor(node);
            const tone = nodeTone(node);
            return L.divIcon({
                className: "asset-marker-shell",
                html: `<span class="asset-marker ${tone} ${active ? "active" : ""}" style="--marker-color:${color}"></span>`,
                iconSize: active ? [30, 30] : [22, 22],
                iconAnchor: active ? [15, 15] : [11, 11],
            });
        }

        function edgeStyle(type) {
            const base = { weight: 2, opacity: 0.68 };
            if (type === "ssl") return { ...base, color: "#ef4444" };
            if (type === "fingerprint") return { ...base, color: "#22c55e", dashArray: "2,7", weight: 3 };
            if (type === "asn") return { ...base, color: "#3b82f6", dashArray: "5,8" };
            if (type === "domain") return { ...base, color: "#a78bfa", dashArray: "8,6", weight: 2.4 };
            if (type === "link") return { ...base, color: "#f59e0b" };
            return { ...base, color: "#64748b" };
        }

        function edgeColor(type) {
            if (type === "ssl") return "#ef4444";
            if (type === "fingerprint") return "#22c55e";
            if (type === "asn") return "#3b82f6";
            if (type === "domain") return "#a78bfa";
            if (type === "link") return "#f59e0b";
            return "#64748b";
        }

        function normalizeEdgeType(type) {
            if (type === "ip") return "asn";
            if (type === "cdn") return "fingerprint";
            if (type === "brand") return "domain";
            return type;
        }

        function edgeLabel(type) {
            const found = EDGE_OPTIONS.find((item) => item.key === type);
            return found ? found.label : type;
        }

        function edgeTooltip(edge, type) {
            const evidence = edge.evidence ? `<small>${escapeHtml(edge.evidence)}</small>` : "";
            return `<strong>${escapeHtml(edgeLabel(type))}</strong>${evidence}`;
        }

        function markerTooltip(node) {
            const tags = nodeTags(node).slice(0, 3).join(" / ") || "未标注";
            return `<strong>${escapeHtml(node.domain || "Unknown")}</strong><small>${escapeHtml(node.ip || "Unknown IP")}</small><em>${escapeHtml(tags)}</em>`;
        }

        function escapeHtml(value) {
            return String(value).replace(/[&<>"']/g, (ch) => ({
                "&": "&amp;",
                "<": "&lt;",
                ">": "&gt;",
                '"': "&quot;",
                "'": "&#39;",
            }[ch]));
        }

        function openDetailPanel(node = selectedNode.value) {
            if (!node) return;
            detailTarget.value = node;
            detailPanelOpen.value = true;
        }

        function closeDetailPanel() {
            detailPanelOpen.value = false;
        }

        function openStarMap(node = selectedNode.value) {
            if (node) selectedNode.value = node;
            starMapOpen.value = true;
            graphSelection.value = null;
            nextTick(() => {
                initStarMap();
            });
        }

        function closeStarMap() {
            starMapOpen.value = false;
            graphSelection.value = null;
            destroyStarMap();
        }

        function initStarMap() {
            if (!window.vis) return;
            destroyStarMap();
            const container = document.getElementById("network-container");
            if (!container) return;
            const data = buildStarMapData();
            graphNodesData = data.nodes;
            graphEdgesData = data.edges;
            network = new vis.Network(container, data, {
                nodes: {
                    shape: "dot",
                    borderWidth: 2,
                    font: { face: "Inter, Microsoft YaHei, sans-serif", color: "#cbd5e1" },
                    shadow: { enabled: true, size: 14 },
                },
                edges: {
                    smooth: { type: "continuous", roundness: 0.35 },
                    font: { color: "#94a3b8", size: 10, strokeWidth: 0 },
                },
                physics: {
                    barnesHut: {
                        gravitationalConstant: -2600,
                        centralGravity: 0.08,
                        springLength: 165,
                        springConstant: 0.045,
                        damping: 0.12,
                    },
                    stabilization: { iterations: 180 },
                },
                interaction: {
                    hover: true,
                    tooltipDelay: 120,
                    zoomView: true,
                    dragView: true,
                },
            });

            network.on("click", (params) => {
                if (!params.nodes.length) {
                    graphSelection.value = null;
                    return;
                }
                const item = graphNodesData.get(params.nodes[0]);
                graphSelection.value = item;
                if (item.asset) selectedNode.value = item.asset;
                network.focus(item.id, {
                    scale: 1.35,
                    animation: { duration: 520, easingFunction: "easeInOutQuad" },
                });
            });

            setTimeout(resetStarMapView, 260);
        }

        function destroyStarMap() {
            if (network) {
                network.destroy();
                network = null;
            }
            graphNodesData = null;
            graphEdgesData = null;
        }

        function buildStarMapData() {
            const graphNodes = new vis.DataSet();
            const graphEdges = new vis.DataSet();
            const byId = Object.fromEntries(nodes.value.map((node) => [node.id, node]));
            const center = selectedNode.value || visibleNodes.value[0] || nodes.value[0];
            const relatedIds = new Set(center ? [center.id] : []);
            const visibleIds = new Set(visibleNodes.value.map((node) => node.id));

            edges.value.forEach((edge) => {
                if (!visibleIds.has(edge.from) || !visibleIds.has(edge.to)) return;
                if (center && (edge.from === center.id || edge.to === center.id)) {
                    relatedIds.add(edge.from);
                    relatedIds.add(edge.to);
                }
            });
            if (relatedIds.size < 2) {
                visibleNodes.value.slice(0, 30).forEach((node) => relatedIds.add(node.id));
            }

            const relationCounts = {};
            const relationAssets = {};
            EDGE_OPTIONS.forEach((item) => {
                relationCounts[item.key] = 0;
                relationAssets[item.key] = new Set();
            });
            edges.value.forEach((edge) => {
                const type = normalizeEdgeType(edge.type);
                if (!edgeFilters.value[type]) return;
                if (!relatedIds.has(edge.from) || !relatedIds.has(edge.to)) return;
                relationCounts[type] = (relationCounts[type] || 0) + 1;
                relationAssets[type]?.add(edge.from);
                relationAssets[type]?.add(edge.to);
            });

            relatedIds.forEach((id) => {
                const node = byId[id];
                if (!node) return;
                const isCenter = center?.id === id;
                graphNodes.add({
                    id,
                    label: node.domain || id,
                    size: isCenter ? 44 : 17,
                    color: {
                        background: markerColor(node),
                        border: isCenter ? "#a5f3fc" : "#475569",
                    },
                    font: { color: isCenter ? "#ffffff" : "#94a3b8", size: isCenter ? 18 : 10, bold: isCenter },
                    shadow: { enabled: true, color: markerColor(node), size: isCenter ? 28 : 10 },
                    group: isCenter ? "center" : "asset",
                    asset: node,
                    title: `${node.domain || id}<br>${node.ip || "Unknown IP"}`,
                });
            });

            EDGE_OPTIONS.forEach((item) => {
                const type = item.key;
                if (!edgeFilters.value[type]) return;
                const count = relationCounts[type] || 0;
                const relationId = `relation:${type}`;
                graphNodes.add({
                    id: relationId,
                    label: `${edgeLabel(type)} ${count}`,
                    size: count ? 24 : 18,
                    color: { background: "rgba(79, 70, 229, 0.86)", border: edgeColor(type) },
                    font: { color: "#c7d2fe", size: 11 },
                    shadow: { enabled: true, color: edgeColor(type), size: count ? 18 : 8 },
                    group: "relation",
                });
                if (center) {
                    graphEdges.add({
                        id: `relation-edge:${type}`,
                        from: center.id,
                        to: relationId,
                        type,
                        color: { color: edgeColor(type), opacity: count ? 0.9 : 0.38 },
                        width: count ? 2.4 : 1.2,
                        dashes: count ? false : [3, 8],
                    });
                }

                Array.from(relationAssets[type] || [])
                    .filter((id) => id !== center?.id && relatedIds.has(id))
                    .slice(0, 16)
                    .forEach((assetId, assetIndex) => {
                        graphEdges.add({
                            id: `relation-asset:${type}:${assetIndex}:${assetId}`,
                            from: relationId,
                            to: assetId,
                            type,
                            color: { color: edgeColor(type), opacity: 0.52 },
                            width: 1.2,
                            dashes: [4, 7],
                    arrows: type === "link" ? "to" : "",
                });
                    });
            });

            edges.value.forEach((edge, index) => {
                const type = normalizeEdgeType(edge.type);
                if (!edgeFilters.value[type]) return;
                if (!relatedIds.has(edge.from) || !relatedIds.has(edge.to)) return;
                const color = edgeColor(type);
                graphEdges.add({
                    id: `edge:${index}:${edge.from}:${edge.to}:${type}`,
                    from: edge.from,
                    to: edge.to,
                    type,
                    color: { color, opacity: 0.86 },
                    width: type === "fingerprint" ? 2.6 : 2,
                    dashes: type === "asn" ? [6, 7] : type === "fingerprint" ? [2, 6] : false,
                    arrows: type === "link" ? "to" : "",
                    title: edge.evidence || edgeLabel(type),
                });
            });

            return { nodes: graphNodes, edges: graphEdges };
        }

        function updateStarMapFilters() {
            refreshLayers();
            if (starMapOpen.value) initStarMap();
        }

        function resetStarMapView() {
            if (!network) return;
            network.fit({
                animation: { duration: 850, easingFunction: "easeInOutQuad" },
            });
            graphSelection.value = null;
        }

        function focusTargetNode(node) {
            if (!validCoord(node)) return;
            const lat = Number(node.lat);
            const lng = Number(node.lng);
            if (mapMode.value === "map" && map) {
                refreshLeafletSize();
                map.setView([lat, lng], Math.max(map.getZoom(), 7), { animate: true });
                setTimeout(() => {
                    markerById.get(node.id)?.openTooltip();
                }, 320);
            }
            if (globe) {
                globe.pointOfView({ lat, lng, altitude: 0.85 }, 1200);
            }
        }

        function selectNode(node, zoom = false) {
            selectedNode.value = node;
            renderMap();
            renderGlobe();
            if (zoom && validCoord(node)) {
                focusTargetNode(node);
            }
        }

        function fitMap() {
            if (isSearchMode.value && selectedNode.value && validCoord(selectedNode.value)) {
                focusTargetNode(selectedNode.value);
                return;
            }
            const points = visibleNodes.value.filter(validCoord).map((node) => [node.lat, node.lng]);
            if (!points.length) return;
            if (mapMode.value === "map") {
                refreshLeafletSize();
                map.fitBounds(points, { padding: [80, 80], maxZoom: 7 });
            } else if (globe) {
                globe.pointOfView({ lat: 22, lng: 18, altitude: isSearchMode.value ? 1.25 : 2.05 }, 900);
            }
        }

        function toggleMapMode() {
            mapMode.value = mapMode.value === "globe" ? "map" : "globe";
            nextTick(() => {
                resizeGlobe();
                refreshLeafletSize();
                refreshLayers();
                fitMap();
                setTimeout(refreshLeafletSize, 380);
            });
        }

        function refreshLayers() {
            renderMap();
            renderGlobe();
        }

        onMounted(async () => {
            initMap();
            initGlobe();
            await fetchTopology("");
            setTimeout(fitMap, 200);
        });

        return {
            nodes,
            edges,
            globalStats,
            metricLabels,
            metricStats,
            searchText,
            selectedTag,
            selectedNode,
            isLoading,
            isProbing,
            loadError,
            isSearchMode,
            mapMode,
            detailPanelOpen,
            detailTarget,
            starMapOpen,
            graphSelection,
            edgeFilters,
            edgeOptions,
            visibleNodes,
            topTags,
            leadingTag,
            riskCount,
            infraCount,
            pageTitle,
            modeLabel,
            runSearch,
            reloadOverview,
            resetWorkspace,
            toggleTag,
            clearTagFilter,
            renderMap,
            refreshLayers,
            fitMap,
            toggleMapMode,
            selectNode,
            openDetailPanel,
            closeDetailPanel,
            openStarMap,
            closeStarMap,
            updateStarMapFilters,
            resetStarMapView,
            primaryTag,
            tagClass,
            nodeTone,
            modelConfidences,
            detailValue,
            nodeDetailValue,
            splitList,
            coordinateText,
            faviconUrl,
            handleFaviconError,
            tagPercent,
        };
    },
}).mount("#app");
