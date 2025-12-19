"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
    Shield, Cloud, Globe, Zap, Lock, Network, Share2, Database,
    Search, Key, Bug, Loader2, Play, AlertTriangle, Server, FileSearch
} from "lucide-react";

const API_URL = "http://localhost:8000";

type ScanType = "external" | "cloud" | "network";
type ScanMode = "fast" | "normal" | "deep" | "stealth";

export default function NewScan() {
    const router = useRouter();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const [formData, setFormData] = useState({
        name: "",
        type: "external" as ScanType,
        target: "",
        mode: "normal" as ScanMode,

        // External Recon Modules
        storage: true,
        services: true,
        subdomains: true,
        crawl: false,
        secrets: true,
        vulns: true,

        // Cloud Authenticated
        provider: "aws",
        privilege_escalation: true,
        attack_paths: true,
        multi_cloud: true,

        // Network Options
        ports: "80,443,8080,8443",
        ssl_scan: false,
    });

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);

        try {
            let endpoint = "";
            let payload: any = {};

            if (formData.type === "external") {
                // Use cloud recon API for external scans
                endpoint = `${API_URL}/api/cloud/scan`;
                payload = {
                    target: formData.target,
                    mode: formData.mode,
                    enable_storage: formData.storage,
                    enable_services: formData.services,
                    enable_subdomains: formData.subdomains,
                    enable_crawl: formData.crawl,
                    enable_secrets: formData.secrets
                };
            } else {
                // Use regular scan API
                endpoint = `${API_URL}/api/scan`;
                payload = formData;
            }

            const res = await fetch(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });

            if (res.ok) {
                const data = await res.json();
                if (formData.type === "external") {
                    router.push(`/cloud/${data.job_id}`);
                } else {
                    router.push("/scan/history");
                }
            } else {
                const err = await res.json();
                setError(err.detail || "Failed to start scan");
            }
        } catch (err) {
            console.error(err);
            setError("Cannot connect to backend. Is it running?");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{ maxWidth: "900px", margin: "0 auto" }}>
            <h1 style={{ fontSize: "2rem", fontWeight: "700", marginBottom: "0.5rem" }}>
                New Scan
            </h1>
            <p style={{ color: "var(--text-secondary)", marginBottom: "2rem" }}>
                Configure and launch a new cloud attack surface scan
            </p>

            {error && (
                <div style={{
                    padding: "1rem",
                    marginBottom: "1.5rem",
                    background: "rgba(255, 0, 85, 0.1)",
                    border: "1px solid var(--accent-danger)",
                    borderRadius: "8px",
                    color: "var(--accent-danger)",
                    display: "flex",
                    alignItems: "center",
                    gap: "0.75rem"
                }}>
                    <AlertTriangle size={20} />
                    {error}
                </div>
            )}

            <form onSubmit={handleSubmit} className="glass-card" style={{ padding: "2rem" }}>

                {/* Scan Name */}
                <div style={{ marginBottom: "1.5rem" }}>
                    <label style={{ display: "block", marginBottom: "0.5rem", color: "var(--text-secondary)" }}>
                        Scan Name
                    </label>
                    <input
                        type="text"
                        required
                        placeholder="e.g. Q4 Cloud Audit - Acme Corp"
                        value={formData.name}
                        onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                        style={{
                            width: "100%", padding: "0.75rem", background: "rgba(0,0,0,0.3)",
                            border: "1px solid var(--border-color)", borderRadius: "8px", color: "white"
                        }}
                    />
                </div>

                {/* Scan Type Selection */}
                <div style={{ marginBottom: "1.5rem" }}>
                    <label style={{ display: "block", marginBottom: "0.75rem", color: "var(--text-secondary)" }}>
                        Scan Type
                    </label>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "1rem" }}>
                        <ScanTypeCard
                            icon={Search}
                            title="External Recon"
                            description="Subdomain, storage, secrets"
                            selected={formData.type === "external"}
                            onClick={() => setFormData({ ...formData, type: "external" })}
                            color="#00f2ff"
                        />
                        <ScanTypeCard
                            icon={Cloud}
                            title="Cloud Audit"
                            description="AWS, Azure, GCP with creds"
                            selected={formData.type === "cloud"}
                            onClick={() => setFormData({ ...formData, type: "cloud" })}
                            color="#7000ff"
                        />
                        <ScanTypeCard
                            icon={Globe}
                            title="Network Scan"
                            description="IP, CIDR, port scanning"
                            selected={formData.type === "network"}
                            onClick={() => setFormData({ ...formData, type: "network" })}
                            color="#00ff9d"
                        />
                    </div>
                </div>

                {/* Target Input */}
                <div style={{ marginBottom: "1.5rem" }}>
                    <label style={{ display: "block", marginBottom: "0.5rem", color: "var(--text-secondary)" }}>
                        {formData.type === "external" ? "Target (domain, keyword, or company)" :
                            formData.type === "cloud" ? "Cloud Provider" : "Target (IP/Domain/CIDR)"}
                    </label>
                    {formData.type === "cloud" ? (
                        <select
                            value={formData.provider}
                            onChange={(e) => setFormData({ ...formData, provider: e.target.value })}
                            style={{
                                width: "100%", padding: "0.75rem", background: "rgba(0,0,0,0.3)",
                                border: "1px solid var(--border-color)", borderRadius: "8px", color: "white"
                            }}
                        >
                            <option value="aws">AWS (Amazon Web Services)</option>
                            <option value="azure">Microsoft Azure</option>
                            <option value="gcp">Google Cloud Platform</option>
                            <option value="all">All Connected Providers</option>
                        </select>
                    ) : (
                        <input
                            type="text"
                            required
                            placeholder={formData.type === "external" ? "e.g. acme-corp or example.com" : "e.g. 192.168.1.0/24"}
                            value={formData.target}
                            onChange={(e) => setFormData({ ...formData, target: e.target.value })}
                            style={{
                                width: "100%", padding: "0.75rem", background: "rgba(0,0,0,0.3)",
                                border: "1px solid var(--border-color)", borderRadius: "8px", color: "white"
                            }}
                        />
                    )}
                </div>

                {/* Scan Mode (for External) */}
                {formData.type === "external" && (
                    <div style={{ marginBottom: "1.5rem" }}>
                        <label style={{ display: "block", marginBottom: "0.75rem", color: "var(--text-secondary)" }}>
                            Scan Mode
                        </label>
                        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "0.75rem" }}>
                            {[
                                { mode: "fast", label: " Fast", desc: "Quick discovery" },
                                { mode: "normal", label: " Normal", desc: "Balanced" },
                                { mode: "deep", label: " Deep", desc: "Thorough" },
                                { mode: "stealth", label: " Stealth", desc: "DNS-only" }
                            ].map((m) => (
                                <button
                                    key={m.mode}
                                    type="button"
                                    onClick={() => setFormData({ ...formData, mode: m.mode as ScanMode })}
                                    style={{
                                        padding: "0.75rem",
                                        background: formData.mode === m.mode ? "rgba(0, 242, 255, 0.1)" : "rgba(255,255,255,0.02)",
                                        border: formData.mode === m.mode ? "1px solid var(--accent-primary)" : "1px solid var(--border-color)",
                                        borderRadius: "8px",
                                        color: formData.mode === m.mode ? "var(--accent-primary)" : "var(--text-secondary)",
                                        cursor: "pointer",
                                        textAlign: "center"
                                    }}
                                >
                                    <div style={{ fontWeight: "600" }}>{m.label}</div>
                                    <div style={{ fontSize: "0.75rem", opacity: 0.7 }}>{m.desc}</div>
                                </button>
                            ))}
                        </div>
                    </div>
                )}

                {/* Module Selection */}
                <h3 style={{
                    fontSize: "1rem", fontWeight: "600", marginBottom: "1rem",
                    display: "flex", alignItems: "center", gap: "0.5rem", marginTop: "1.5rem"
                }}>
                    <Shield size={18} color="var(--accent-primary)" />
                    {formData.type === "external" ? "Recon Modules" :
                        formData.type === "cloud" ? "Audit Modules" : "Network Options"}
                </h3>

                {formData.type === "external" && (
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", marginBottom: "2rem" }}>
                        <Toggle label=" Storage Buckets" sublabel="S3, Azure, GCS" checked={formData.storage} onChange={(v) => setFormData({ ...formData, storage: v })} />
                        <Toggle label="️ Cloud Services" sublabel="100+ services" checked={formData.services} onChange={(v) => setFormData({ ...formData, services: v })} />
                        <Toggle label=" Subdomains" sublabel="Subfinder + DNSx" checked={formData.subdomains} onChange={(v) => setFormData({ ...formData, subdomains: v })} />
                        <Toggle label="️ Web Crawling" sublabel="Katana headless" checked={formData.crawl} onChange={(v) => setFormData({ ...formData, crawl: v })} />
                        <Toggle label=" Secret Detection" sublabel="TruffleHog 50+ patterns" checked={formData.secrets} onChange={(v) => setFormData({ ...formData, secrets: v })} />
                        <Toggle label="️ Vulnerabilities" sublabel="Nuclei scanner" checked={formData.vulns} onChange={(v) => setFormData({ ...formData, vulns: v })} />
                    </div>
                )}

                {formData.type === "cloud" && (
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", marginBottom: "2rem" }}>
                        <Toggle label="IAM Privilege Escalation" sublabel="Detect privilege chains" checked={formData.privilege_escalation} onChange={(v) => setFormData({ ...formData, privilege_escalation: v })} />
                        <Toggle label="Attack Path Analysis" sublabel="Graph-based paths" checked={formData.attack_paths} onChange={(v) => setFormData({ ...formData, attack_paths: v })} />
                        <Toggle label="Multi-Cloud Lateral" sublabel="Cross-provider movement" checked={formData.multi_cloud} onChange={(v) => setFormData({ ...formData, multi_cloud: v })} />
                        <Toggle label="Secrets Scanning" sublabel="Environment & config" checked={formData.secrets} onChange={(v) => setFormData({ ...formData, secrets: v })} danger />
                    </div>
                )}

                {formData.type === "network" && (
                    <div style={{ marginBottom: "2rem" }}>
                        <div style={{ marginBottom: "1rem" }}>
                            <label style={{ display: "block", marginBottom: "0.5rem", color: "var(--text-secondary)" }}>
                                Ports to Scan
                            </label>
                            <input
                                type="text"
                                placeholder="80,443,8080,8443"
                                value={formData.ports}
                                onChange={(e) => setFormData({ ...formData, ports: e.target.value })}
                                style={{
                                    width: "100%", padding: "0.75rem", background: "rgba(0,0,0,0.3)",
                                    border: "1px solid var(--border-color)", borderRadius: "8px", color: "white"
                                }}
                            />
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
                            <Toggle label="Subdomain Enumeration" sublabel="Find subdomains" checked={formData.subdomains} onChange={(v) => setFormData({ ...formData, subdomains: v })} />
                            <Toggle label="SSL/TLS Analysis" sublabel="Certificate inspection" checked={formData.ssl_scan} onChange={(v) => setFormData({ ...formData, ssl_scan: v })} />
                        </div>
                    </div>
                )}

                {/* Submit Button */}
                <button
                    type="submit"
                    disabled={loading}
                    style={{
                        width: "100%", padding: "1rem", borderRadius: "8px", border: "none",
                        background: loading ? "#333" : "linear-gradient(135deg, var(--accent-primary), #0088ff)",
                        color: loading ? "var(--text-muted)" : "black",
                        fontWeight: "700", fontSize: "1rem", cursor: loading ? "not-allowed" : "pointer",
                        display: "flex", alignItems: "center", justifyContent: "center", gap: "0.5rem"
                    }}
                >
                    {loading ? (
                        <>
                            <Loader2 size={20} className="animate-spin" />
                            Starting Scan...
                        </>
                    ) : (
                        <>
                            <Play size={20} />
                            Launch Scan
                        </>
                    )}
                </button>
            </form>

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

interface ScanTypeCardProps {
    icon: any;
    title: string;
    description: string;
    selected: boolean;
    onClick: () => void;
    color: string;
}

function ScanTypeCard({ icon: Icon, title, description, selected, onClick, color }: ScanTypeCardProps) {
    return (
        <div
            onClick={onClick}
            style={{
                padding: "1.25rem",
                borderRadius: "12px",
                cursor: "pointer",
                border: selected ? `1px solid ${color}` : "1px solid var(--border-color)",
                background: selected ? `${color}10` : "transparent",
                transition: "all 0.2s"
            }}
        >
            <Icon size={24} style={{ color: selected ? color : "var(--text-muted)", marginBottom: "0.5rem" }} />
            <h3 style={{ fontWeight: "600", fontSize: "0.95rem", color: selected ? "white" : "var(--text-secondary)" }}>{title}</h3>
            <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>{description}</p>
        </div>
    );
}

interface ToggleProps {
    label: string;
    sublabel?: string;
    checked: boolean;
    onChange: (checked: boolean) => void;
    danger?: boolean;
}

function Toggle({ label, sublabel, checked, onChange, danger = false }: ToggleProps) {
    return (
        <div
            onClick={() => onChange(!checked)}
            style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "0.875rem", borderRadius: "8px", cursor: "pointer",
                background: checked ? (danger ? "rgba(255, 0, 85, 0.1)" : "rgba(0, 242, 255, 0.05)") : "rgba(255,255,255,0.02)",
                border: checked ? (danger ? "1px solid var(--accent-danger)" : "1px solid var(--accent-primary)") : "1px solid transparent"
            }}
        >
            <div>
                <div style={{ fontSize: "0.9rem", color: checked ? "white" : "var(--text-secondary)" }}>{label}</div>
                {sublabel && <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{sublabel}</div>}
            </div>
            <div style={{
                width: "36px", height: "20px", borderRadius: "10px",
                background: checked ? (danger ? "var(--accent-danger)" : "var(--accent-primary)") : "#333",
                position: "relative", transition: "all 0.2s"
            }}>
                <div style={{
                    width: "16px", height: "16px", borderRadius: "50%", background: "white",
                    position: "absolute", top: "2px", left: checked ? "18px" : "2px", transition: "all 0.2s"
                }} />
            </div>
        </div>
    );
}
