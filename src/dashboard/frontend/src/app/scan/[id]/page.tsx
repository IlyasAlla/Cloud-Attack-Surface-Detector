"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Graph from "../../../components/Graph";
import StatCard from "../../../components/StatCard";
import { Shield, AlertTriangle, Server, Clock, Bot, XCircle, Loader2, Download, FileText, FileSpreadsheet } from "lucide-react";
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

export default function ScanReport() {
    const params = useParams();
    const [scan, setScan] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [aiModalOpen, setAiModalOpen] = useState(false);
    const [aiLoading, setAiLoading] = useState(false);
    const [aiContent, setAiContent] = useState("");
    const [exportOpen, setExportOpen] = useState(false);
    const [selectedAsset, setSelectedAsset] = useState<any>(null);

    const handleNodeClick = (nodeData: any) => {
        // Find full asset data if possible, or use node data
        const fullAsset = scan?.assets?.find((a: any) => a.id === nodeData.id);
        setSelectedAsset(fullAsset || nodeData);
    };

    const handleExport = (type: 'csv' | 'pdf') => {
        window.open(`http://localhost:8000/api/scans/${params.id}/export/${type}`, '_blank');
        setExportOpen(false);
    };

    const handleAskAI = async (asset: any) => {
        setAiModalOpen(true);
        setAiLoading(true);
        setAiContent("");

        try {
            const res = await fetch("http://localhost:8000/api/ai/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    asset: {
                        id: asset.id,
                        resource_type: asset.resource_type,
                        provider: asset.provider,
                        metadata: asset.metadata
                    },
                    vulnerabilities: asset.vulnerabilities
                })
            });
            const data = await res.json();
            setAiContent(data.analysis);
        } catch (err) {
            console.error(err);
            setAiContent("Failed to connect to AI Agent.");
        } finally {
            setAiLoading(false);
        }
    };

    const handleGenerateReport = async () => {
        setAiModalOpen(true);
        setAiLoading(true);
        setAiContent("");

        try {
            const res = await fetch("http://localhost:8000/api/ai/scan_report", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scan_data: scan })
            });
            const data = await res.json();
            setAiContent(data.report);
        } catch (err) {
            console.error(err);
            setAiContent("Failed to generate AI report.");
        } finally {
            setAiLoading(false);
        }
    };

    const handleDownloadAI = () => {
        if (!aiContent) return;
        const blob = new Blob([aiContent], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ai_report_${params.id}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    const handleSimulateBreach = async (startNodeId: string) => {
        try {
            const scanId = Array.isArray(params.id) ? params.id[0] : params.id;
            const res = await fetch("http://127.0.0.1:8000/api/graph/simulate_breach", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scan_id: scanId, start_node_id: startNodeId })
            });
            if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
            const data = await res.json();

            // Update graph elements to reflect compromised state
            if (scan && scan.graph) {
                const newGraph = scan.graph.map((el: any) => {
                    const newEl = { ...el };
                    if (newEl.group === 'nodes' && data.compromised_nodes.includes(newEl.data.id)) {
                        newEl.data.compromised = "true";
                    }
                    if (newEl.group === 'edges' && data.traversed_edges.includes(newEl.data.id)) {
                        newEl.data.compromised = "true";
                    }
                    return newEl;
                });
                setScan({ ...scan, graph: newGraph });
            }
        } catch (err) {
            console.error("Simulation failed:", err);
        }
    };

    useEffect(() => {
        if (!params.id) return;

        let isMounted = true;
        let timeoutId: NodeJS.Timeout;

        const fetchScan = async () => {
            try {
                const res = await fetch(`http://localhost:8000/api/scans/${params.id}`);
                const data = await res.json();

                if (isMounted) {
                    setScan(data);
                    setLoading(false);

                    // Poll if running
                    if (data.status === "running") {
                        timeoutId = setTimeout(fetchScan, 3000);
                    }
                }
            } catch (err) {
                console.error(err);
                if (isMounted) setLoading(false);
            }
        };

        fetchScan();

        return () => {
            isMounted = false;
            clearTimeout(timeoutId);
        };
    }, [params.id]);

    if (loading) return <div style={{ padding: "2rem", textAlign: "center" }}>Loading Mission Data...</div>;
    if (!scan) return <div style={{ padding: "2rem", textAlign: "center" }}>Scan not found</div>;

    return (
        <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "2rem" }}>
                <div>
                    <h1 style={{ fontSize: "2rem", fontWeight: "700", marginBottom: "0.5rem" }}>{scan.name}</h1>
                    <div style={{ display: "flex", gap: "1rem", color: "var(--text-secondary)" }}>
                        <span style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}><Clock size={16} /> {scan.timestamp}</span>
                        <span style={{ textTransform: "uppercase", letterSpacing: "1px", color: "var(--accent-primary)" }}>{scan.type} SCAN</span>
                    </div>
                </div>
                <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
                    <button
                        onClick={handleGenerateReport}
                        style={{
                            display: "flex", alignItems: "center", gap: "0.5rem",
                            padding: "0.5rem 1rem", borderRadius: "8px",
                            background: "linear-gradient(45deg, var(--accent-primary), #a855f7)", color: "white",
                            border: "none", cursor: "pointer", fontWeight: "600",
                            boxShadow: "0 0 10px rgba(168, 85, 247, 0.3)"
                        }}
                    >
                        <Bot size={16} /> AI Report
                    </button>
                    <div style={{ position: "relative" }}>
                        <button
                            onClick={() => setExportOpen(!exportOpen)}
                            style={{
                                display: "flex", alignItems: "center", gap: "0.5rem",
                                padding: "0.5rem 1rem", borderRadius: "8px",
                                background: "rgba(255, 255, 255, 0.1)", color: "white",
                                border: "1px solid var(--border-color)", cursor: "pointer"
                            }}
                        >
                            <Download size={16} /> Export
                        </button>
                        {exportOpen && (
                            <div className="glass-card" style={{
                                position: "absolute", top: "110%", right: 0,
                                width: "150px", padding: "0.5rem", zIndex: 10,
                                display: "flex", flexDirection: "column", gap: "0.5rem"
                            }}>
                                <button
                                    onClick={() => handleExport('pdf')}
                                    style={{
                                        display: "flex", alignItems: "center", gap: "0.5rem",
                                        padding: "0.5rem", background: "none", border: "none",
                                        color: "var(--text-primary)", cursor: "pointer", textAlign: "left", width: "100%"
                                    }}
                                    className="hover:bg-white/10 rounded"
                                >
                                    <FileText size={16} /> PDF Report
                                </button>
                                <button
                                    onClick={() => handleExport('csv')}
                                    style={{
                                        display: "flex", alignItems: "center", gap: "0.5rem",
                                        padding: "0.5rem", background: "none", border: "none",
                                        color: "var(--text-primary)", cursor: "pointer", textAlign: "left", width: "100%"
                                    }}
                                    className="hover:bg-white/10 rounded"
                                >
                                    <FileSpreadsheet size={16} /> CSV Data
                                </button>
                            </div>
                        )}
                    </div>
                    <div style={{
                        padding: "0.5rem 1rem", borderRadius: "8px",
                        background: scan.status === "completed" ? "rgba(0, 255, 157, 0.1)" : "rgba(0, 242, 255, 0.1)",
                        color: scan.status === "completed" ? "var(--accent-success)" : "var(--accent-primary)",
                        fontWeight: "600"
                    }}>
                        {scan.status}
                    </div>
                </div>
            </div>

            {/* Running State Handling */}
            {scan.status === "running" && !scan.summary ? (
                <div className="glass-card" style={{ padding: "3rem", textAlign: "center", marginBottom: "2rem" }}>
                    <div style={{ fontSize: "1.5rem", marginBottom: "1rem", color: "var(--accent-primary)" }}>Scan in Progress...</div>
                    <p style={{ color: "var(--text-secondary)" }}>The orchestrator is currently scanning the target. Results will appear here once completed.</p>
                    <div style={{
                        marginTop: "1.5rem", display: "inline-flex", alignItems: "center", gap: "0.5rem",
                        padding: "0.5rem 1rem", background: "rgba(0, 242, 255, 0.1)",
                        borderRadius: "20px", color: "var(--accent-primary)", fontSize: "0.85rem"
                    }}>
                        <div className="animate-pulse" style={{ width: "8px", height: "8px", borderRadius: "50%", background: "currentColor" }}></div>
                        Auto-refreshing live data...
                    </div>
                </div>
            ) : (
                <>
                    {/* Stats */}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1.5rem", marginBottom: "2rem" }}>
                        <StatCard title="Total Assets" value={scan.summary?.total_assets || 0} icon={Server} />
                        <StatCard title="Vulnerable Assets" value={scan.summary?.vuln_assets || 0} icon={AlertTriangle} trendType="negative" />
                        <StatCard title="Providers" value={scan.summary?.providers?.length || 0} icon={Shield} />
                    </div>
                </>
            )}

            {/* Assets Table */}
            <div className="glass-card" style={{ padding: "1.5rem", marginBottom: "2rem" }}>
                <h2 style={{ fontSize: "1.25rem", fontWeight: "600", marginBottom: "1rem" }}>Discovered Assets</h2>
                <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                        <thead>
                            <tr style={{ textAlign: "left", color: "var(--text-secondary)", borderBottom: "1px solid var(--border-color)" }}>
                                <th style={{ padding: "1rem 0" }}>Resource ID</th>
                                <th>Type</th>
                                <th>Region</th>
                                <th>IP Address</th>
                                <th>Metadata</th>
                                <th>Vulnerabilities</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(scan.assets || []).map((asset: any) => (
                                <tr key={asset.id} style={{ borderBottom: "1px solid var(--border-color)" }}>
                                    <td style={{ padding: "1rem 0", fontFamily: "monospace", fontWeight: "600" }}>{asset.id}</td>
                                    <td>
                                        <span style={{
                                            padding: "0.2rem 0.5rem", borderRadius: "4px",
                                            background: "rgba(255, 255, 255, 0.05)", fontSize: "0.85rem"
                                        }}>
                                            {asset.resource_type}
                                        </span>
                                    </td>
                                    <td style={{ color: "var(--text-secondary)" }}>{asset.region}</td>
                                    <td style={{ fontFamily: "monospace" }}>{asset.ip_address}</td>
                                    <td style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
                                        {asset.metadata && Object.entries(asset.metadata).map(([key, value]) => (
                                            <div key={key} style={{ marginBottom: "0.2rem" }}>
                                                <span style={{ color: "var(--text-muted)" }}>{key}:</span> <span style={{ color: "var(--text-primary)" }}>{String(value)}</span>
                                            </div>
                                        ))}
                                    </td>
                                    <td>
                                        {Object.keys(asset.vulnerabilities).length > 0 ? (
                                            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                                                {Object.entries(asset.vulnerabilities).map(([port, vulns]: [string, any]) => (
                                                    <div key={port}>
                                                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.1rem" }}>
                                                            {port === "Identity" || port === "Storage" || port === "Network" || port === "API" || port === "Secrets" ? port : `Port ${port}`}
                                                        </div>
                                                        <div style={{ display: "flex", gap: "0.3rem", flexWrap: "wrap" }}>
                                                            {Array.isArray(vulns) && vulns.map((v: string, idx: number) => (
                                                                <span key={idx} style={{
                                                                    padding: "0.2rem 0.5rem", borderRadius: "4px",
                                                                    background: "rgba(255, 0, 85, 0.1)", color: "var(--accent-danger)", fontSize: "0.8rem",
                                                                    border: "1px solid rgba(255, 0, 85, 0.2)"
                                                                }}>
                                                                    {v}
                                                                </span>
                                                            ))}
                                                        </div>
                                                    </div>
                                                ))}
                                                <button
                                                    onClick={() => handleAskAI(asset)}
                                                    style={{
                                                        marginTop: "0.5rem", padding: "0.3rem 0.6rem", fontSize: "0.75rem",
                                                        background: "linear-gradient(45deg, var(--accent-primary), #a855f7)",
                                                        border: "none", borderRadius: "4px", color: "white", cursor: "pointer",
                                                        display: "flex", alignItems: "center", gap: "0.3rem", width: "fit-content"
                                                    }}
                                                >
                                                    <Bot size={12} /> Ask AI
                                                </button>
                                            </div>
                                        ) : (
                                            <span style={{ color: "var(--accent-success)", display: "flex", alignItems: "center", gap: "0.3rem" }}>
                                                <Shield size={14} /> Secure
                                            </span>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Graph */}
            <div className="glass-card" style={{ padding: "1.5rem", marginBottom: "2rem" }}>
                <h2 style={{ fontSize: "1.25rem", fontWeight: "600", marginBottom: "1rem" }}>Attack Surface Graph</h2>
                {scan.graph && scan.graph.length > 0 ? (
                    <Graph elements={scan.graph} onNodeClick={handleNodeClick} />
                ) : (
                    <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-muted)" }}>No graph data available</div>
                )}
            </div>

            {/* Asset Details Side Panel */}
            {selectedAsset && (
                <div style={{
                    position: "fixed", top: 0, right: 0, bottom: 0, width: "400px",
                    background: "rgba(10, 10, 15, 0.95)", backdropFilter: "blur(10px)",
                    borderLeft: "1px solid var(--border-color)", padding: "2rem",
                    zIndex: 1000, overflowY: "auto", boxShadow: "-5px 0 20px rgba(0,0,0,0.5)"
                }}>
                    <button
                        onClick={() => setSelectedAsset(null)}
                        style={{ position: "absolute", top: "1rem", right: "1rem", background: "none", border: "none", color: "var(--text-secondary)", cursor: "pointer" }}
                    >
                        <XCircle size={24} />
                    </button>

                    <h2 style={{ fontSize: "1.5rem", fontWeight: "700", marginBottom: "0.5rem", wordBreak: "break-all" }}>
                        {selectedAsset.id}
                    </h2>
                    <div style={{
                        display: "inline-block", padding: "0.2rem 0.5rem", borderRadius: "4px",
                        background: "rgba(255, 255, 255, 0.1)", fontSize: "0.85rem", marginBottom: "1.5rem"
                    }}>
                        {selectedAsset.resource_type || selectedAsset.label}
                    </div>

                    {selectedAsset.ip_address && (
                        <div style={{ marginBottom: "1.5rem" }}>
                            <h3 style={{ fontSize: "0.9rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>IP ADDRESS</h3>
                            <div style={{ fontFamily: "monospace" }}>{selectedAsset.ip_address}</div>
                        </div>
                    )}

                    {selectedAsset.metadata && (
                        <div style={{ marginBottom: "1.5rem" }}>
                            <h3 style={{ fontSize: "0.9rem", color: "var(--text-secondary)", marginBottom: "0.3rem" }}>METADATA</h3>
                            {Object.entries(selectedAsset.metadata).map(([key, value]) => (
                                <div key={key} style={{ marginBottom: "0.2rem", fontSize: "0.9rem" }}>
                                    <span style={{ color: "var(--text-muted)" }}>{key}:</span> {String(value)}
                                </div>
                            ))}
                        </div>
                    )}

                    <div style={{ marginBottom: "2rem" }}>
                        <h3 style={{ fontSize: "0.9rem", color: "var(--text-secondary)", marginBottom: "0.5rem" }}>VULNERABILITIES</h3>
                        {selectedAsset.vulnerabilities && Object.keys(selectedAsset.vulnerabilities).length > 0 ? (
                            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                                {Object.entries(selectedAsset.vulnerabilities).map(([port, vulns]: [string, any]) => (
                                    <div key={port} style={{ background: "rgba(255, 0, 85, 0.05)", padding: "0.5rem", borderRadius: "4px" }}>
                                        <div style={{ fontSize: "0.75rem", color: "var(--accent-danger)", marginBottom: "0.2rem", fontWeight: "600" }}>
                                            {port === "Identity" || port === "Storage" || port === "Network" || port === "API" || port === "Secrets" ? port : `Port ${port}`}
                                        </div>
                                        {Array.isArray(vulns) && vulns.map((v: string, idx: number) => (
                                            <div key={idx} style={{ fontSize: "0.85rem", color: "var(--text-primary)" }}>• {v}</div>
                                        ))}
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div style={{ color: "var(--accent-success)", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                                <Shield size={16} /> No vulnerabilities detected
                            </div>
                        )}
                    </div>

                    <div style={{ display: "flex", gap: "1rem" }}>
                        <button
                            onClick={() => handleAskAI(selectedAsset)}
                            style={{
                                flex: 1, padding: "0.8rem",
                                background: "linear-gradient(45deg, var(--accent-primary), #a855f7)",
                                border: "none", borderRadius: "8px", color: "white", cursor: "pointer",
                                display: "flex", alignItems: "center", justifyContent: "center", gap: "0.5rem", fontWeight: "600"
                            }}
                        >
                            <Bot size={18} /> Analyze with AI
                        </button>
                        <button
                            onClick={() => handleSimulateBreach(selectedAsset.id)}
                            style={{
                                flex: 1, padding: "0.8rem",
                                background: "rgba(255, 0, 0, 0.2)",
                                border: "1px solid #ff0000", borderRadius: "8px", color: "#ff0000", cursor: "pointer",
                                display: "flex", alignItems: "center", justifyContent: "center", gap: "0.5rem", fontWeight: "600"
                            }}
                        >
                            <AlertTriangle size={18} /> Simulate Breach
                        </button>
                    </div>
                </div>
            )}

            {/* AI Analysis Modal */}
            {aiModalOpen && (
                <div style={{
                    position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
                    background: "rgba(0,0,0,0.8)", backdropFilter: "blur(5px)",
                    display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000
                }}>
                    <div className="glass-card" style={{ width: "800px", maxWidth: "90vw", maxHeight: "80vh", overflowY: "auto", padding: "2rem", position: "relative" }}>
                        <button
                            onClick={() => setAiModalOpen(false)}
                            style={{ position: "absolute", top: "1rem", right: "1rem", background: "none", border: "none", color: "white", cursor: "pointer" }}
                        >
                            <XCircle size={24} />
                        </button>

                        <h2 style={{ fontSize: "1.5rem", fontWeight: "700", marginBottom: "1rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                            <Bot size={24} color="var(--accent-primary)" /> AI Tactical Analysis
                        </h2>

                        {!aiLoading && aiContent && (
                            <button
                                onClick={handleDownloadAI}
                                style={{
                                    position: "absolute", top: "1rem", right: "4rem",
                                    display: "flex", alignItems: "center", gap: "0.5rem",
                                    padding: "0.4rem 0.8rem", borderRadius: "6px",
                                    background: "rgba(255,255,255,0.1)", color: "white",
                                    border: "1px solid var(--border-color)", cursor: "pointer", fontSize: "0.85rem"
                                }}
                            >
                                <Download size={14} /> Download
                            </button>
                        )}

                        {aiLoading ? (
                            <div style={{ textAlign: "center", padding: "4rem" }}>
                                <Loader2 size={48} className="animate-spin" style={{ color: "var(--accent-primary)", marginBottom: "1rem" }} />
                                <p>Consulting Neural Network...</p>
                            </div>
                        ) : (
                            <div className="markdown-content" style={{ lineHeight: "1.6", color: "var(--text-primary)" }}>
                                <ReactMarkdown
                                    remarkPlugins={[remarkGfm]}
                                    components={{
                                        h1: ({ node, ...props }) => <h1 style={{ fontSize: "1.8rem", color: "var(--accent-primary)", borderBottom: "1px solid var(--border-color)", paddingBottom: "0.5rem", marginTop: "1.5rem", marginBottom: "1rem" }} {...props} />,
                                        h2: ({ node, ...props }) => <h2 style={{ fontSize: "1.4rem", color: "white", marginTop: "1.5rem", marginBottom: "0.8rem" }} {...props} />,
                                        h3: ({ node, ...props }) => <h3 style={{ fontSize: "1.1rem", color: "var(--text-secondary)", marginTop: "1rem", marginBottom: "0.5rem" }} {...props} />,
                                        ul: ({ node, ...props }) => <ul style={{ paddingLeft: "1.5rem", marginBottom: "1rem" }} {...props} />,
                                        li: ({ node, ...props }) => <li style={{ marginBottom: "0.5rem" }} {...props} />,
                                        strong: ({ node, ...props }) => <strong style={{ color: "var(--accent-primary)", fontWeight: "600" }} {...props} />,
                                        p: ({ node, ...props }) => <p style={{ marginBottom: "1rem" }} {...props} />,
                                        code: ({ node, ...props }) => <code style={{ background: "rgba(255,255,255,0.1)", padding: "0.2rem 0.4rem", borderRadius: "4px", fontFamily: "monospace", fontSize: "0.9em", color: "#ff79c6" }} {...props} />,
                                        blockquote: ({ node, ...props }) => (
                                            <blockquote style={{ borderLeft: "4px solid var(--accent-primary)", paddingLeft: "1rem", marginLeft: 0, fontStyle: "italic", color: "var(--text-secondary)", background: "rgba(255,255,255,0.05)", padding: "1rem", borderRadius: "0 8px 8px 0" }} {...props} />
                                        ),
                                        table: ({ node, ...props }) => (
                                            <div style={{ overflowX: "auto", marginBottom: "1.5rem", borderRadius: "8px", border: "1px solid var(--border-color)" }}>
                                                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }} {...props} />
                                            </div>
                                        ),
                                        thead: ({ node, ...props }) => <thead style={{ background: "rgba(255,255,255,0.05)" }} {...props} />,
                                        tbody: ({ node, ...props }) => <tbody {...props} />,
                                        tr: ({ node, ...props }) => <tr style={{ borderBottom: "1px solid var(--border-color)" }} {...props} />,
                                        th: ({ node, ...props }) => <th style={{ padding: "0.75rem", textAlign: "left", fontWeight: "600", color: "var(--text-primary)" }} {...props} />,
                                        td: ({ node, ...props }) => <td style={{ padding: "0.75rem", color: "var(--text-secondary)" }} {...props} />,
                                        hr: ({ node, ...props }) => <hr style={{ border: "none", height: "1px", background: "linear-gradient(90deg, transparent, var(--border-color), transparent)", margin: "2rem 0" }} {...props} />,
                                        pre: ({ node, ...props }) => <pre style={{ background: "#1e1e2e", padding: "1rem", borderRadius: "8px", overflowX: "auto", marginBottom: "1rem", border: "1px solid var(--border-color)" }} {...props} />,
                                    }}
                                >
                                    {aiContent}
                                </ReactMarkdown>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
