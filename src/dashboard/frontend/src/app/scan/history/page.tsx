"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
    History, Search, Trash2, Download, ExternalLink, RefreshCw,
    CheckCircle, XCircle, Loader2, Clock, Cloud, Globe, Shield
} from "lucide-react";

const API_URL = "http://localhost:8000";

interface Scan {
    id: string;
    name?: string;
    type: string;
    target?: string;
    keyword?: string;
    status: string;
    timestamp?: string;
    started_at?: string;
    completed_at?: string;
    progress?: number;
    assets_count?: number;
    vuln_count?: number;
    summary?: any;
}

export default function ScanHistory() {
    const [scans, setScans] = useState<Scan[]>([]);
    const [cloudJobs, setCloudJobs] = useState<Scan[]>([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState<"all" | "cloud" | "external" | "network">("all");
    const [searchTerm, setSearchTerm] = useState("");

    const fetchScans = async () => {
        setLoading(true);
        try {
            const [scansRes, cloudRes] = await Promise.all([
                fetch(`${API_URL}/api/scans`).catch(() => null),
                fetch(`${API_URL}/api/cloud/jobs`).catch(() => null)
            ]);

            if (scansRes?.ok) {
                const data = await scansRes.json();
                setScans(Array.isArray(data) ? data : []);
            }

            if (cloudRes?.ok) {
                const data = await cloudRes.json();
                setCloudJobs(data.jobs || []);
            }
        } catch (err) {
            console.error("Failed to fetch scans", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchScans();
        const interval = setInterval(fetchScans, 10000); // Refresh every 10s
        return () => clearInterval(interval);
    }, []);

    const deleteScan = async (id: string, isCloud: boolean) => {
        if (!confirm("Are you sure you want to delete this scan?")) return;

        try {
            const endpoint = isCloud
                ? `${API_URL}/api/cloud/jobs/${id}`
                : `${API_URL}/api/scans/${id}`;

            await fetch(endpoint, { method: "DELETE" });
            fetchScans();
        } catch (err) {
            console.error("Failed to delete scan", err);
        }
    };

    // Combine scans
    const allScans: Scan[] = [
        ...cloudJobs.map(j => ({ ...j, type: j.type || "cloud", source: "cloud" })),
        ...scans.map(s => ({ ...s, source: "legacy" }))
    ].sort((a, b) => {
        const dateA = new Date(a.started_at || a.timestamp || 0);
        const dateB = new Date(b.started_at || b.timestamp || 0);
        return dateB.getTime() - dateA.getTime();
    });

    // Filter scans
    const filteredScans = allScans.filter(scan => {
        // Type filter
        if (filter !== "all") {
            if (filter === "cloud" && !["cloud", "cloud_scan"].includes(scan.type)) return false;
            if (filter === "external" && !["external", "storage_enum", "cloud_scan"].includes(scan.type)) return false;
            if (filter === "network" && scan.type !== "network") return false;
        }

        // Search filter
        if (searchTerm) {
            const search = searchTerm.toLowerCase();
            const target = (scan.target || scan.keyword || scan.name || "").toLowerCase();
            if (!target.includes(search)) return false;
        }

        return true;
    });

    const getStatusBadge = (status: string) => {
        const styles: Record<string, { bg: string; color: string; icon: any }> = {
            completed: { bg: "rgba(0, 255, 157, 0.1)", color: "var(--accent-success)", icon: CheckCircle },
            running: { bg: "rgba(0, 242, 255, 0.1)", color: "var(--accent-primary)", icon: Loader2 },
            failed: { bg: "rgba(255, 0, 85, 0.1)", color: "var(--accent-danger)", icon: XCircle },
            pending: { bg: "rgba(255, 189, 0, 0.1)", color: "var(--accent-warning)", icon: Clock },
        };
        const style = styles[status] || styles.pending;
        const Icon = style.icon;

        return (
            <span style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "0.375rem",
                padding: "0.25rem 0.75rem",
                borderRadius: "20px",
                fontSize: "0.8rem",
                background: style.bg,
                color: style.color
            }}>
                <Icon size={12} className={status === "running" ? "animate-spin" : ""} />
                {status}
            </span>
        );
    };

    const getTypeIcon = (type: string) => {
        if (["cloud", "cloud_scan"].includes(type)) return <Cloud size={16} style={{ color: "#7000ff" }} />;
        if (["storage_enum", "secrets_scan"].includes(type)) return <Shield size={16} style={{ color: "#00f2ff" }} />;
        return <Globe size={16} style={{ color: "#00ff9d" }} />;
    };

    return (
        <div>
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "2rem" }}>
                <div>
                    <h1 style={{ fontSize: "2rem", fontWeight: "700", display: "flex", alignItems: "center", gap: "0.75rem" }}>
                        <History size={28} />
                        Scan History
                    </h1>
                    <p style={{ color: "var(--text-secondary)", marginTop: "0.5rem" }}>
                        View and manage all your cloud reconnaissance scans
                    </p>
                </div>
                <button
                    onClick={fetchScans}
                    style={{
                        display: "flex", alignItems: "center", gap: "0.5rem",
                        padding: "0.75rem 1.25rem", background: "transparent",
                        border: "1px solid var(--border-color)", borderRadius: "8px",
                        color: "var(--text-primary)", cursor: "pointer"
                    }}
                >
                    <RefreshCw size={16} />
                    Refresh
                </button>
            </div>

            {/* Filters */}
            <div style={{
                display: "flex", gap: "1rem", marginBottom: "1.5rem",
                flexWrap: "wrap", alignItems: "center"
            }}>
                <div style={{ position: "relative", flex: 1, minWidth: "200px" }}>
                    <Search size={18} style={{
                        position: "absolute", left: "1rem", top: "50%",
                        transform: "translateY(-50%)", color: "var(--text-muted)"
                    }} />
                    <input
                        type="text"
                        placeholder="Search scans..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        style={{
                            width: "100%", padding: "0.75rem 1rem 0.75rem 2.75rem",
                            background: "rgba(0,0,0,0.3)", border: "1px solid var(--border-color)",
                            borderRadius: "8px", color: "white"
                        }}
                    />
                </div>

                <div style={{ display: "flex", gap: "0.5rem" }}>
                    {["all", "external", "cloud", "network"].map((f) => (
                        <button
                            key={f}
                            onClick={() => setFilter(f as any)}
                            style={{
                                padding: "0.5rem 1rem",
                                background: filter === f ? "rgba(0, 242, 255, 0.1)" : "transparent",
                                border: filter === f ? "1px solid var(--accent-primary)" : "1px solid var(--border-color)",
                                borderRadius: "6px",
                                color: filter === f ? "var(--accent-primary)" : "var(--text-secondary)",
                                cursor: "pointer",
                                textTransform: "capitalize"
                            }}
                        >
                            {f}
                        </button>
                    ))}
                </div>
            </div>

            {/* Scans Table */}
            <div className="glass-card" style={{ padding: "1.5rem" }}>
                {loading ? (
                    <div style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)" }}>
                        <Loader2 size={32} className="animate-spin" style={{ marginBottom: "1rem" }} />
                        <p>Loading scans...</p>
                    </div>
                ) : filteredScans.length === 0 ? (
                    <div style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)" }}>
                        <History size={48} style={{ marginBottom: "1rem", opacity: 0.5 }} />
                        <p>No scans found</p>
                        <Link href="/scan/new" style={{ color: "var(--accent-primary)", marginTop: "0.5rem", display: "inline-block" }}>
                            Start a new scan →
                        </Link>
                    </div>
                ) : (
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                        <thead>
                            <tr style={{ textAlign: "left", color: "var(--text-secondary)", borderBottom: "1px solid var(--border-color)" }}>
                                <th style={{ padding: "1rem 0" }}>Target</th>
                                <th>Type</th>
                                <th>Status</th>
                                <th>Results</th>
                                <th>Date</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredScans.map((scan) => {
                                const isCloud = ["cloud", "cloud_scan", "storage_enum", "secrets_scan"].includes(scan.type);
                                const link = isCloud ? `/cloud/${scan.id}` : `/scan/${scan.id}`;

                                return (
                                    <tr key={scan.id} style={{ borderBottom: "1px solid var(--border-color)" }}>
                                        <td style={{ padding: "1rem 0" }}>
                                            <Link href={link} style={{ fontWeight: "500", color: "white" }}>
                                                {scan.target || scan.keyword || scan.name || "Untitled"}
                                            </Link>
                                        </td>
                                        <td>
                                            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                                                {getTypeIcon(scan.type)}
                                                <span style={{ textTransform: "capitalize", color: "var(--text-secondary)", fontSize: "0.9rem" }}>
                                                    {scan.type.replace("_", " ")}
                                                </span>
                                            </div>
                                        </td>
                                        <td>{getStatusBadge(scan.status)}</td>
                                        <td style={{ color: "var(--text-secondary)" }}>
                                            {scan.assets_count !== undefined ? `${scan.assets_count} assets` :
                                                scan.summary?.total !== undefined ? `${scan.summary.total} items` : "-"}
                                        </td>
                                        <td style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>
                                            {new Date(scan.started_at || scan.timestamp || "").toLocaleString()}
                                        </td>
                                        <td>
                                            <div style={{ display: "flex", gap: "0.5rem" }}>
                                                <Link
                                                    href={link}
                                                    style={{
                                                        padding: "0.375rem", borderRadius: "6px",
                                                        background: "rgba(0, 242, 255, 0.1)",
                                                        color: "var(--accent-primary)",
                                                        display: "flex"
                                                    }}
                                                >
                                                    <ExternalLink size={16} />
                                                </Link>
                                                <button
                                                    onClick={() => deleteScan(scan.id, isCloud)}
                                                    style={{
                                                        padding: "0.375rem", borderRadius: "6px",
                                                        background: "rgba(255, 0, 85, 0.1)",
                                                        border: "none", color: "var(--accent-danger)",
                                                        cursor: "pointer", display: "flex"
                                                    }}
                                                >
                                                    <Trash2 size={16} />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                )}
            </div>

            <style jsx>{`
                .animate-spin {
                    animation: spin 1s linear infinite;
                }
                @keyframes spin {
                    from { transform: rotate(0deg); }
                    to { transform: rotate(360deg); }
                }
            `}</style>
        </div>
    );
}
