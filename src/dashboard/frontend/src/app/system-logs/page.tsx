"use client";

import { useEffect, useState, useRef } from "react";
import { Terminal, RefreshCw, Download, Loader2, AlertTriangle, Info, AlertCircle } from "lucide-react";

const API_URL = "http://localhost:8000";

interface LogEntry {
    timestamp: string;
    level: string;
    message: string;
    raw: string;
}

export default function LogsPage() {
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [loading, setLoading] = useState(true);
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [filter, setFilter] = useState<"all" | "info" | "warning" | "error">("all");
    const logRef = useRef<HTMLDivElement>(null);

    const fetchLogs = async () => {
        try {
            const res = await fetch(`${API_URL}/api/logs?lines=200`);
            if (res.ok) {
                const data = await res.json();
                const parsed = (data.logs || []).map((line: string) => parseLine(line));
                setLogs(parsed);
            }
        } catch (err) {
            console.error("Failed to fetch logs", err);
        } finally {
            setLoading(false);
        }
    };

    const parseLine = (line: string): LogEntry => {
        const match = line.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) - (\S+) - (\w+) - (.*)$/);
        if (match) {
            return {
                timestamp: match[1],
                level: match[3].toLowerCase(),
                message: match[4],
                raw: line
            };
        }
        return { timestamp: "", level: "info", message: line, raw: line };
    };

    useEffect(() => {
        fetchLogs();
    }, []);

    useEffect(() => {
        if (autoRefresh) {
            const interval = setInterval(fetchLogs, 3000);
            return () => clearInterval(interval);
        }
    }, [autoRefresh]);

    useEffect(() => {
        if (logRef.current) {
            logRef.current.scrollTop = logRef.current.scrollHeight;
        }
    }, [logs]);

    const filteredLogs = logs.filter(log => {
        if (filter === "all") return true;
        return log.level === filter;
    });

    const getLevelColor = (level: string) => {
        switch (level.toLowerCase()) {
            case "error": return "var(--accent-danger)";
            case "warning": return "var(--accent-warning)";
            case "info": return "var(--accent-primary)";
            default: return "var(--text-secondary)";
        }
    };

    const getLevelIcon = (level: string) => {
        switch (level.toLowerCase()) {
            case "error": return <AlertCircle size={14} />;
            case "warning": return <AlertTriangle size={14} />;
            case "info": return <Info size={14} />;
            default: return null;
        }
    };

    const downloadLogs = () => {
        const content = logs.map(l => l.raw).join("\n");
        const blob = new Blob([content], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `cloud-asf-logs-${new Date().toISOString().split("T")[0]}.log`;
        a.click();
    };

    return (
        <div style={{ height: "calc(100vh - 120px)", display: "flex", flexDirection: "column" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
                <div>
                    <h1 style={{ fontSize: "2rem", fontWeight: "700", display: "flex", alignItems: "center", gap: "0.75rem" }}>
                        <Terminal size={28} />
                        System Logs
                    </h1>
                    <p style={{ color: "var(--text-secondary)", marginTop: "0.5rem" }}>
                        Real-time backend logs and activity
                    </p>
                </div>

                <div style={{ display: "flex", gap: "0.75rem" }}>
                    <button
                        onClick={() => setAutoRefresh(!autoRefresh)}
                        style={{
                            display: "flex", alignItems: "center", gap: "0.5rem",
                            padding: "0.5rem 1rem",
                            background: autoRefresh ? "rgba(0, 255, 157, 0.1)" : "transparent",
                            border: `1px solid ${autoRefresh ? "var(--accent-success)" : "var(--border-color)"}`,
                            borderRadius: "6px",
                            color: autoRefresh ? "var(--accent-success)" : "var(--text-secondary)",
                            cursor: "pointer"
                        }}
                    >
                        <RefreshCw size={16} />
                        Auto-refresh
                    </button>
                    <button
                        onClick={downloadLogs}
                        style={{
                            display: "flex", alignItems: "center", gap: "0.5rem",
                            padding: "0.5rem 1rem",
                            background: "transparent",
                            border: "1px solid var(--border-color)",
                            borderRadius: "6px",
                            color: "var(--text-primary)",
                            cursor: "pointer"
                        }}
                    >
                        <Download size={16} />
                        Export
                    </button>
                </div>
            </div>

            <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem" }}>
                {["all", "info", "warning", "error"].map((f) => (
                    <button
                        key={f}
                        onClick={() => setFilter(f as any)}
                        style={{
                            padding: "0.375rem 0.875rem",
                            background: filter === f ? "rgba(0, 242, 255, 0.1)" : "transparent",
                            border: filter === f ? "1px solid var(--accent-primary)" : "1px solid var(--border-color)",
                            borderRadius: "6px",
                            color: filter === f ? "var(--accent-primary)" : "var(--text-secondary)",
                            cursor: "pointer",
                            textTransform: "capitalize",
                            fontSize: "0.85rem"
                        }}
                    >
                        {f}
                    </button>
                ))}
            </div>

            <div
                ref={logRef}
                className="glass-card"
                style={{
                    flex: 1,
                    padding: "1rem",
                    overflow: "auto",
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: "0.8rem",
                    lineHeight: "1.6"
                }}
            >
                {loading ? (
                    <div style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>
                        <Loader2 size={24} />
                        <p style={{ marginTop: "0.5rem" }}>Loading logs...</p>
                    </div>
                ) : filteredLogs.length === 0 ? (
                    <div style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>
                        <Terminal size={32} style={{ opacity: 0.5, marginBottom: "0.5rem" }} />
                        <p>No logs found</p>
                    </div>
                ) : (
                    filteredLogs.map((log, idx) => (
                        <div
                            key={idx}
                            style={{
                                display: "flex",
                                gap: "0.75rem",
                                padding: "0.375rem 0",
                                borderBottom: "1px solid rgba(255,255,255,0.03)"
                            }}
                        >
                            {log.timestamp && (
                                <span style={{ color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                                    {log.timestamp.split(",")[0]}
                                </span>
                            )}
                            <span style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "0.25rem",
                                color: getLevelColor(log.level),
                                minWidth: "70px",
                                textTransform: "uppercase"
                            }}>
                                {getLevelIcon(log.level)}
                                {log.level}
                            </span>
                            <span style={{ color: "var(--text-primary)" }}>
                                {log.message}
                            </span>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
