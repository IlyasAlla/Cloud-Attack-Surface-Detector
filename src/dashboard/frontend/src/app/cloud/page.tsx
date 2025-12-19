"use client";

import { useEffect, useState } from "react";
import {
    Cloud, Database, Key, Globe, Play, RefreshCw, AlertTriangle,
    CheckCircle, Clock, Loader2, Shield, Server, Search, Zap,
    Target, TrendingUp, Activity, ExternalLink, ArrowRight, Cpu
} from "lucide-react";
import Link from "next/link";

const API_URL = "http://localhost:8000";

interface CloudJob {
    id: string;
    type: string;
    status: string;
    target?: string;
    keyword?: string;
    started_at: string;
    progress: number;
    summary?: any;
}

interface CloudStats {
    total_scans: number;
    completed_scans: number;
    total_storage_found: number;
    total_secrets_found: number;
}

export default function CloudDashboard() {
    const [stats, setStats] = useState<CloudStats | null>(null);
    const [jobs, setJobs] = useState<CloudJob[]>([]);
    const [serviceCount, setServiceCount] = useState(0);
    const [loading, setLoading] = useState(true);
    const [scanTarget, setScanTarget] = useState("");
    const [scanMode, setScanMode] = useState("normal");
    const [isScanning, setIsScanning] = useState(false);

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, []);

    const fetchData = async () => {
        try {
            const [statsRes, jobsRes, servicesRes] = await Promise.all([
                fetch(`${API_URL}/api/cloud/stats`).catch(() => null),
                fetch(`${API_URL}/api/cloud/jobs`).catch(() => null),
                fetch(`${API_URL}/api/cloud/services`).catch(() => null)
            ]);

            if (statsRes?.ok) setStats(await statsRes.json());
            if (jobsRes?.ok) {
                const data = await jobsRes.json();
                setJobs(data.jobs || []);
            }
            if (servicesRes?.ok) {
                const data = await servicesRes.json();
                setServiceCount(data.total || 0);
            }
        } catch (err) {
            console.error("Failed to fetch", err);
        } finally {
            setLoading(false);
        }
    };

    const startQuickScan = async () => {
        if (!scanTarget.trim()) return;
        setIsScanning(true);
        try {
            const res = await fetch(`${API_URL}/api/cloud/scan`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    target: scanTarget,
                    mode: scanMode,
                    enable_storage: true,
                    enable_services: true,
                    enable_subdomains: true,
                    enable_secrets: true
                })
            });
            if (res.ok) {
                setScanTarget("");
                fetchData();
            }
        } catch (err) {
            console.error(err);
        } finally {
            setIsScanning(false);
        }
    };

    const runningJobs = jobs.filter(j => j.status === "running");
    const completedJobs = jobs.filter(j => j.status === "completed").slice(0, 5);

    return (
        <div>
            {/* Hero Header */}
            <div style={{
                background: "linear-gradient(135deg, rgba(0, 242, 255, 0.05) 0%, rgba(112, 0, 255, 0.05) 100%)",
                borderRadius: "16px",
                padding: "2rem",
                marginBottom: "2rem",
                border: "1px solid rgba(0, 242, 255, 0.1)"
            }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <div>
                        <h1 style={{
                            fontSize: "2.5rem",
                            fontWeight: "700",
                            marginBottom: "0.5rem",
                            background: "linear-gradient(135deg, #00f2ff, #7000ff)",
                            WebkitBackgroundClip: "text",
                            WebkitTextFillColor: "transparent"
                        }}>
                            Cloud Reconnaissance
                        </h1>
                        <p style={{ color: "var(--text-secondary)", fontSize: "1.1rem", maxWidth: "600px" }}>
                            Discover cloud assets, exposed storage, secrets, and services across AWS, Azure, GCP, and 10+ providers
                        </p>
                    </div>
                    <button
                        onClick={fetchData}
                        style={{
                            display: "flex", alignItems: "center", gap: "0.5rem",
                            padding: "0.75rem 1.25rem", background: "rgba(0,0,0,0.3)",
                            border: "1px solid var(--border-color)", borderRadius: "8px",
                            color: "var(--text-primary)", cursor: "pointer"
                        }}
                    >
                        <RefreshCw size={16} />
                        Refresh
                    </button>
                </div>

                {/* Quick Stats in Header */}
                <div style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(4, 1fr)",
                    gap: "1rem",
                    marginTop: "1.5rem"
                }}>
                    <QuickStat icon={Target} label="Scans" value={stats?.total_scans || 0} color="#00f2ff" />
                    <QuickStat icon={Database} label="Storage Found" value={stats?.total_storage_found || 0} color="#f59e0b" />
                    <QuickStat icon={Key} label="Secrets" value={stats?.total_secrets_found || 0} color="#ef4444" />
                    <QuickStat icon={Cpu} label="Services" value={serviceCount} color="#22c55e" />
                </div>
            </div>

            {/* Main Content Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 400px", gap: "1.5rem" }}>
                {/* Left Column */}
                <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
                    {/* Quick Scan Card */}
                    <div className="glass-card" style={{ padding: "1.5rem" }}>
                        <h2 style={{
                            fontSize: "1.25rem", fontWeight: "600", marginBottom: "1rem",
                            display: "flex", alignItems: "center", gap: "0.5rem"
                        }}>
                            <Zap size={20} style={{ color: "var(--accent-primary)" }} />
                            Quick Scan
                        </h2>
                        <div style={{ display: "flex", gap: "0.75rem" }}>
                            <input
                                type="text"
                                value={scanTarget}
                                onChange={(e) => setScanTarget(e.target.value)}
                                onKeyDown={(e) => e.key === "Enter" && startQuickScan()}
                                placeholder="Enter domain or keyword (e.g., acme-corp)"
                                style={{
                                    flex: 1, padding: "0.875rem 1rem",
                                    background: "rgba(0,0,0,0.3)", border: "1px solid var(--border-color)",
                                    borderRadius: "8px", color: "white", fontSize: "1rem"
                                }}
                            />
                            <select
                                value={scanMode}
                                onChange={(e) => setScanMode(e.target.value)}
                                style={{
                                    padding: "0.875rem 1rem", background: "rgba(0,0,0,0.3)",
                                    border: "1px solid var(--border-color)", borderRadius: "8px",
                                    color: "white", minWidth: "140px"
                                }}
                            >
                                <option value="fast"> Fast</option>
                                <option value="normal"> Normal</option>
                                <option value="deep"> Deep</option>
                            </select>
                            <button
                                onClick={startQuickScan}
                                disabled={isScanning || !scanTarget.trim()}
                                style={{
                                    padding: "0.875rem 1.5rem",
                                    background: isScanning ? "#333" : "linear-gradient(135deg, #00f2ff, #0088ff)",
                                    border: "none", borderRadius: "8px",
                                    color: isScanning ? "var(--text-muted)" : "black",
                                    fontWeight: "600", cursor: isScanning ? "not-allowed" : "pointer",
                                    display: "flex", alignItems: "center", gap: "0.5rem"
                                }}
                            >
                                {isScanning ? <Loader2 size={18} className="animate-spin" /> : <Play size={18} />}
                                Scan
                            </button>
                        </div>
                        <Link href="/scan/new" style={{
                            display: "inline-flex", alignItems: "center", gap: "0.25rem",
                            color: "var(--accent-primary)", fontSize: "0.9rem", marginTop: "1rem"
                        }}>
                            Advanced options <ArrowRight size={14} />
                        </Link>
                    </div>

                    {/* Feature Cards */}
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                        <FeatureCard
                            icon={Database}
                            title="Storage Enumeration"
                            description="S3, Azure Blob, GCS buckets with permission checks"
                            color="#f59e0b"
                            href="/scan/new"
                        />
                        <FeatureCard
                            icon={Key}
                            title="Secret Scanning"
                            description="50+ secret types with live verification"
                            color="#ef4444"
                            href="/scan/new"
                        />
                        <FeatureCard
                            icon={Globe}
                            title="Subdomain Discovery"
                            description="Passive + active subdomain enumeration"
                            color="#22c55e"
                            href="/scan/new"
                        />
                        <FeatureCard
                            icon={Server}
                            title={`${serviceCount}+ Cloud Services`}
                            description="AWS, Azure, GCP, Cloudflare, and more"
                            color="#7000ff"
                            href="/scan/new"
                        />
                    </div>

                    {/* Running Jobs */}
                    {runningJobs.length > 0 && (
                        <div className="glass-card" style={{ padding: "1.5rem" }}>
                            <h2 style={{
                                fontSize: "1.25rem", fontWeight: "600", marginBottom: "1rem",
                                display: "flex", alignItems: "center", gap: "0.5rem"
                            }}>
                                <Activity size={20} style={{ color: "var(--accent-primary)" }} />
                                Running Scans ({runningJobs.length})
                            </h2>
                            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                                {runningJobs.map((job) => (
                                    <Link
                                        key={job.id}
                                        href={`/cloud/${job.id}`}
                                        style={{
                                            display: "block", padding: "1rem",
                                            background: "rgba(0, 242, 255, 0.05)",
                                            border: "1px solid rgba(0, 242, 255, 0.2)",
                                            borderRadius: "8px", textDecoration: "none"
                                        }}
                                    >
                                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
                                            <span style={{ fontWeight: "500", color: "white" }}>{job.target || job.keyword}</span>
                                            <span style={{ fontSize: "0.85rem", color: "var(--accent-primary)" }}>{job.progress}%</span>
                                        </div>
                                        <div style={{
                                            height: "6px", background: "rgba(0,0,0,0.3)",
                                            borderRadius: "3px", overflow: "hidden"
                                        }}>
                                            <div style={{
                                                width: `${job.progress}%`, height: "100%",
                                                background: "linear-gradient(90deg, #00f2ff, #7000ff)",
                                                transition: "width 0.3s"
                                            }} />
                                        </div>
                                    </Link>
                                ))}
                            </div>
                        </div>
                    )}
                </div>

                {/* Right Column - Recent Scans */}
                <div className="glass-card" style={{ padding: "1.5rem", height: "fit-content" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
                        <h2 style={{ fontSize: "1.25rem", fontWeight: "600" }}>Recent Scans</h2>
                        <Link href="/scan/history" style={{ color: "var(--accent-primary)", fontSize: "0.9rem" }}>
                            View all
                        </Link>
                    </div>

                    {loading ? (
                        <div style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>
                            <Loader2 size={24} className="animate-spin" />
                        </div>
                    ) : jobs.length === 0 ? (
                        <div style={{ textAlign: "center", padding: "2rem", color: "var(--text-muted)" }}>
                            <Cloud size={48} style={{ opacity: 0.3, marginBottom: "0.5rem" }} />
                            <p>No scans yet</p>
                            <p style={{ fontSize: "0.85rem" }}>Run your first scan above!</p>
                        </div>
                    ) : (
                        <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                            {jobs.slice(0, 8).map((job) => (
                                <Link
                                    key={job.id}
                                    href={`/cloud/${job.id}`}
                                    style={{
                                        display: "flex", alignItems: "center", gap: "0.75rem",
                                        padding: "0.75rem", background: "rgba(255,255,255,0.02)",
                                        borderRadius: "8px", textDecoration: "none",
                                        transition: "background 0.2s"
                                    }}
                                >
                                    <StatusIcon status={job.status} />
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{
                                            fontWeight: "500", color: "white",
                                            whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis"
                                        }}>
                                            {job.target || job.keyword}
                                        </div>
                                        <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                                            {formatTimeAgo(job.started_at)}
                                        </div>
                                    </div>
                                    {job.status === "completed" && job.summary && (
                                        <div style={{
                                            fontSize: "0.75rem", color: "var(--text-secondary)",
                                            textAlign: "right"
                                        }}>
                                            <div>{job.summary.subdomain_count || 0} subs</div>
                                            <div>{job.summary.service_count || 0} services</div>
                                        </div>
                                    )}
                                </Link>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            <style jsx>{`
                .animate-spin { animation: spin 1s linear infinite; }
                @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
            `}</style>
        </div>
    );
}

function QuickStat({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
    return (
        <div style={{
            display: "flex", alignItems: "center", gap: "0.75rem",
            padding: "0.75rem 1rem", background: "rgba(0,0,0,0.2)",
            borderRadius: "8px"
        }}>
            <Icon size={20} style={{ color }} />
            <div>
                <div style={{ fontSize: "1.25rem", fontWeight: "700", color: "white" }}>{value.toLocaleString()}</div>
                <div style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>{label}</div>
            </div>
        </div>
    );
}

function FeatureCard({ icon: Icon, title, description, color, href }: {
    icon: any; title: string; description: string; color: string; href: string;
}) {
    return (
        <Link
            href={href}
            className="glass-card"
            style={{
                padding: "1.25rem", display: "block", textDecoration: "none",
                transition: "border-color 0.2s, transform 0.2s"
            }}
        >
            <Icon size={24} style={{ color, marginBottom: "0.75rem" }} />
            <h3 style={{ fontWeight: "600", marginBottom: "0.25rem", color: "white" }}>{title}</h3>
            <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", lineHeight: "1.4" }}>{description}</p>
        </Link>
    );
}

function StatusIcon({ status }: { status: string }) {
    const config: Record<string, { icon: any; color: string; className?: string }> = {
        completed: { icon: CheckCircle, color: "#22c55e" },
        running: { icon: Loader2, color: "#00f2ff", className: "animate-spin" },
        failed: { icon: AlertTriangle, color: "#ef4444" },
        pending: { icon: Clock, color: "#f59e0b" }
    };
    const { icon: Icon, color, className } = config[status] || config.pending;
    return <Icon size={16} style={{ color }} className={className} />;
}

function formatTimeAgo(dateString: string): string {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
    return date.toLocaleDateString();
}
