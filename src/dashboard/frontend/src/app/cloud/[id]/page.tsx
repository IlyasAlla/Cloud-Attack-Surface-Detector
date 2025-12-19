"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
    ArrowLeft,
    Cloud,
    Database,
    Key,
    Globe,
    CheckCircle,
    AlertTriangle,
    Loader2,
    Download,
    ExternalLink,
    Lock,
    Unlock
} from "lucide-react";
import Link from "next/link";

const API_URL = "http://localhost:8000";

interface JobResult {
    id: string;
    type: string;
    status: string;
    target?: string;
    keyword?: string;
    started_at: string;
    completed_at?: string;
    progress: number;
    phase?: string;
    results?: {
        storage?: any[];
        services?: any[];
        subdomains?: string[];
        endpoints?: any[];
        secrets?: any[];
        vulnerabilities?: any[];
    };
    summary?: {
        storage_count?: number;
        service_count?: number;
        subdomain_count?: number;
        endpoint_count?: number;
        secret_count?: number;
        vuln_count?: number;
        total?: number;
        public?: number;
        protected?: number;
        verified?: number;
    };
    by_provider?: Record<string, any[]>;
    by_permission?: {
        public?: any[];
        protected?: any[];
        unknown?: any[];
    };
    error?: string;
}

export default function CloudJobDetail() {
    const params = useParams();
    const router = useRouter();
    const jobId = params.id as string;

    const [job, setJob] = useState<JobResult | null>(null);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState<"summary" | "storage" | "services" | "secrets" | "subdomains">("summary");

    useEffect(() => {
        fetchJob();
        const interval = setInterval(() => {
            if (job?.status !== "completed" && job?.status !== "failed") {
                fetchJob();
            }
        }, 2000);
        return () => clearInterval(interval);
    }, [jobId, job?.status]);

    const fetchJob = async () => {
        try {
            const res = await fetch(`${API_URL}/api/cloud/jobs/${jobId}`);
            if (res.ok) {
                setJob(await res.json());
            }
        } catch (err) {
            console.error("Failed to fetch job", err);
        } finally {
            setLoading(false);
        }
    };

    const deleteJob = async () => {
        if (confirm("Are you sure you want to delete this job?")) {
            await fetch(`${API_URL}/api/cloud/jobs/${jobId}`, { method: "DELETE" });
            router.push("/cloud");
        }
    };

    const exportResults = () => {
        if (!job?.results) return;
        const blob = new Blob([JSON.stringify(job.results, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `cloud-scan-${jobId}.json`;
        a.click();
    };

    if (loading) {
        return (
            <div style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "50vh" }}>
                <Loader2 size={48} className="animate-spin" style={{ color: "var(--accent-primary)" }} />
            </div>
        );
    }

    if (!job) {
        return (
            <div style={{ textAlign: "center", padding: "3rem" }}>
                <AlertTriangle size={48} style={{ color: "var(--accent-danger)", marginBottom: "1rem" }} />
                <h2>Job Not Found</h2>
                <Link href="/cloud" style={{ color: "var(--accent-primary)" }}>← Back to Cloud Dashboard</Link>
            </div>
        );
    }

    return (
        <div>
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "2rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
                    <Link href="/cloud" style={{ color: "var(--text-secondary)" }}>
                        <ArrowLeft size={24} />
                    </Link>
                    <div>
                        <h1 style={{ fontSize: "1.75rem", fontWeight: "700" }}>
                            {job.target || job.keyword}
                        </h1>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginTop: "0.5rem" }}>
                            <span style={{
                                padding: "0.25rem 0.75rem",
                                borderRadius: "20px",
                                fontSize: "0.85rem",
                                background: job.status === "completed" ? "rgba(34, 197, 94, 0.15)" :
                                    job.status === "running" ? "rgba(0, 242, 255, 0.15)" : "rgba(239, 68, 68, 0.15)",
                                color: job.status === "completed" ? "#22c55e" :
                                    job.status === "running" ? "var(--accent-primary)" : "#ef4444"
                            }}>
                                {job.status === "running" && <Loader2 size={12} className="animate-spin" style={{ marginRight: "0.5rem" }} />}
                                {job.status}
                            </span>
                            <span style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>
                                {job.type} • Started {new Date(job.started_at).toLocaleString()}
                            </span>
                        </div>
                    </div>
                </div>

                <div style={{ display: "flex", gap: "0.75rem" }}>
                    <button
                        onClick={exportResults}
                        disabled={job.status !== "completed"}
                        style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "0.5rem",
                            padding: "0.75rem 1.25rem",
                            background: "transparent",
                            border: "1px solid var(--border-color)",
                            borderRadius: "8px",
                            color: "var(--text-primary)",
                            cursor: "pointer"
                        }}
                    >
                        <Download size={16} />
                        Export JSON
                    </button>
                    <button
                        onClick={deleteJob}
                        style={{
                            padding: "0.75rem 1.25rem",
                            background: "rgba(239, 68, 68, 0.15)",
                            border: "1px solid rgba(239, 68, 68, 0.3)",
                            borderRadius: "8px",
                            color: "#ef4444",
                            cursor: "pointer"
                        }}
                    >
                        Delete
                    </button>
                </div>
            </div>

            {/* Progress Bar (if running) */}
            {job.status === "running" && (
                <div className="glass-card" style={{ padding: "1.25rem", marginBottom: "1.5rem" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.75rem" }}>
                        <span style={{ fontWeight: "500" }}>{job.phase || "Scanning..."}</span>
                        <span style={{ color: "var(--accent-primary)", fontWeight: "600" }}>{job.progress}%</span>
                    </div>
                    <div style={{
                        width: "100%",
                        height: "8px",
                        background: "var(--bg-tertiary)",
                        borderRadius: "4px",
                        overflow: "hidden"
                    }}>
                        <div style={{
                            width: `${job.progress}%`,
                            height: "100%",
                            background: "linear-gradient(90deg, var(--accent-primary), #0088ff)",
                            transition: "width 0.3s"
                        }} />
                    </div>
                </div>
            )}

            {/* Summary Stats */}
            {job.summary && (
                <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "1rem", marginBottom: "1.5rem" }}>
                    <StatBox icon={<Database size={20} />} label="Storage" value={job.summary.storage_count || job.summary.total || 0} />
                    <StatBox icon={<Cloud size={20} />} label="Services" value={job.summary.service_count || 0} />
                    <StatBox icon={<Globe size={20} />} label="Subdomains" value={job.summary.subdomain_count || 0} />
                    <StatBox icon={<ExternalLink size={20} />} label="Endpoints" value={job.summary.endpoint_count || 0} />
                    <StatBox icon={<Key size={20} />} label="Secrets" value={job.summary.secret_count || job.summary.verified || 0} color="#ef4444" />
                </div>
            )}

            {/* Tabs */}
            <div style={{
                display: "flex",
                gap: "0.5rem",
                marginBottom: "1.5rem",
                borderBottom: "1px solid var(--border-color)",
                paddingBottom: "1rem"
            }}>
                {["summary", "storage", "services", "secrets", "subdomains"].map((tab) => (
                    <button
                        key={tab}
                        onClick={() => setActiveTab(tab as any)}
                        style={{
                            padding: "0.5rem 1rem",
                            background: activeTab === tab ? "rgba(0, 242, 255, 0.1)" : "transparent",
                            border: activeTab === tab ? "1px solid var(--accent-primary)" : "1px solid transparent",
                            borderRadius: "6px",
                            color: activeTab === tab ? "var(--accent-primary)" : "var(--text-secondary)",
                            cursor: "pointer",
                            textTransform: "capitalize"
                        }}
                    >
                        {tab}
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            <div className="glass-card" style={{ padding: "1.5rem" }}>
                {activeTab === "summary" && (
                    <div>
                        <h3 style={{ marginBottom: "1rem" }}>Scan Summary</h3>
                        <div style={{ display: "grid", gap: "1rem" }}>
                            {job.summary?.public !== undefined && job.summary.public > 0 && (
                                <div className="alert-box critical">
                                    <AlertTriangle size={20} />
                                    <span><strong>{job.summary.public}</strong> publicly accessible storage buckets found!</span>
                                </div>
                            )}
                            {job.summary?.secret_count && job.summary.secret_count > 0 && (
                                <div className="alert-box critical">
                                    <Key size={20} />
                                    <span><strong>{job.summary.secret_count}</strong> secrets/credentials detected!</span>
                                </div>
                            )}
                            {job.error && (
                                <div className="alert-box error">
                                    <AlertTriangle size={20} />
                                    <span>Error: {job.error}</span>
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {activeTab === "storage" && (
                    <div>
                        <h3 style={{ marginBottom: "1rem" }}>Storage Assets</h3>
                        <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                            {(job.results?.storage || job.by_permission?.public || []).length === 0 ? (
                                <p style={{ color: "var(--text-muted)" }}>No storage assets found.</p>
                            ) : (
                                [...(job.results?.storage || []), ...(job.by_permission?.public || [])].slice(0, 20).map((item: any, idx: number) => (
                                    <div
                                        key={idx}
                                        style={{
                                            display: "flex",
                                            justifyContent: "space-between",
                                            alignItems: "center",
                                            padding: "1rem",
                                            background: "var(--bg-tertiary)",
                                            borderRadius: "8px"
                                        }}
                                    >
                                        <div>
                                            <div style={{ fontWeight: "500", marginBottom: "0.25rem" }}>{item.url}</div>
                                            <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                                                {item.provider} • Status: {item.status}
                                            </div>
                                        </div>
                                        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                                            {item.permissions?.includes("PUBLIC") ? (
                                                <span style={{ display: "flex", alignItems: "center", gap: "0.25rem", color: "#ef4444" }}>
                                                    <Unlock size={16} />
                                                    Public
                                                </span>
                                            ) : (
                                                <span style={{ display: "flex", alignItems: "center", gap: "0.25rem", color: "#22c55e" }}>
                                                    <Lock size={16} />
                                                    Protected
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                )}

                {activeTab === "services" && (
                    <div>
                        <h3 style={{ marginBottom: "1rem" }}>Cloud Services</h3>
                        <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                            {(job.results?.services || []).length === 0 ? (
                                <p style={{ color: "var(--text-muted)" }}>No cloud services detected.</p>
                            ) : (
                                (job.results?.services || []).map((svc: any, idx: number) => (
                                    <div
                                        key={idx}
                                        style={{
                                            display: "flex",
                                            justifyContent: "space-between",
                                            padding: "0.75rem 1rem",
                                            background: "var(--bg-tertiary)",
                                            borderRadius: "6px"
                                        }}
                                    >
                                        <span>{svc.service} - {svc.url}</span>
                                        <span style={{
                                            fontSize: "0.8rem",
                                            padding: "0.25rem 0.5rem",
                                            borderRadius: "4px",
                                            background: svc.severity === "CRITICAL" ? "rgba(239, 68, 68, 0.2)" : "rgba(245, 158, 11, 0.2)",
                                            color: svc.severity === "CRITICAL" ? "#ef4444" : "#f59e0b"
                                        }}>
                                            {svc.severity}
                                        </span>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                )}

                {activeTab === "secrets" && (
                    <div>
                        <h3 style={{ marginBottom: "1rem" }}>Detected Secrets</h3>
                        <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                            {(job.results?.secrets || []).length === 0 ? (
                                <p style={{ color: "var(--text-muted)" }}>No secrets detected.</p>
                            ) : (
                                (job.results?.secrets || []).map((secret: any, idx: number) => (
                                    <div
                                        key={idx}
                                        style={{
                                            padding: "1rem",
                                            background: "rgba(239, 68, 68, 0.1)",
                                            border: "1px solid rgba(239, 68, 68, 0.3)",
                                            borderRadius: "8px"
                                        }}
                                    >
                                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
                                            <span style={{ fontWeight: "600", color: "#ef4444" }}>{secret.detector || secret.type}</span>
                                            {secret.verified && (
                                                <span style={{
                                                    fontSize: "0.8rem",
                                                    padding: "0.25rem 0.5rem",
                                                    background: "#ef4444",
                                                    color: "#fff",
                                                    borderRadius: "4px"
                                                }}>
                                                    VERIFIED
                                                </span>
                                            )}
                                        </div>
                                        <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
                                            {secret.file || secret.source || "Unknown source"}
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                )}

                {activeTab === "subdomains" && (
                    <div>
                        <h3 style={{ marginBottom: "1rem" }}>Subdomains ({job.results?.subdomains?.length || 0})</h3>
                        <div style={{
                            display: "grid",
                            gridTemplateColumns: "repeat(3, 1fr)",
                            gap: "0.5rem"
                        }}>
                            {(job.results?.subdomains || []).slice(0, 50).map((sub: string, idx: number) => (
                                <div
                                    key={idx}
                                    style={{
                                        padding: "0.5rem 0.75rem",
                                        background: "var(--bg-tertiary)",
                                        borderRadius: "4px",
                                        fontSize: "0.85rem",
                                        fontFamily: "monospace"
                                    }}
                                >
                                    {sub}
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>

            <style jsx>{`
        .alert-box {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          padding: 1rem;
          border-radius: 8px;
        }
        .alert-box.critical {
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid rgba(239, 68, 68, 0.3);
          color: #ef4444;
        }
        .alert-box.error {
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid rgba(239, 68, 68, 0.3);
          color: #ef4444;
        }
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

function StatBox({ icon, label, value, color = "var(--accent-primary)" }: { icon: React.ReactNode; label: string; value: number; color?: string }) {
    return (
        <div className="glass-card" style={{ padding: "1rem", textAlign: "center" }}>
            <div style={{ color, marginBottom: "0.5rem" }}>{icon}</div>
            <div style={{ fontSize: "1.5rem", fontWeight: "700" }}>{value}</div>
            <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>{label}</div>
        </div>
    );
}
