"use client";

import { useEffect, useState } from "react";
import { Activity, Shield, AlertTriangle, Server, RefreshCw, WifiOff, Cloud, Database, Key, Bug } from "lucide-react";
import StatCard from "../components/StatCard";
import Link from "next/link";

const API_URL = "http://localhost:8000";

interface Scan {
  id: string;
  name: string;
  type: string;
  status: string;
  timestamp: string;
  assets_count: number;
  vuln_count: number;
}

interface CloudStats {
  total_scans: number;
  running_scans: number;
  storage_found: number;
  secrets_found: number;
  services_detected: number;
}

export default function Dashboard() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [cloudJobs, setCloudJobs] = useState<any[]>([]);
  const [cloudStats, setCloudStats] = useState<CloudStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
      const [scansRes, cloudRes, statsRes] = await Promise.all([
        fetch(`${API_URL}/api/scans`, { signal: controller.signal }).catch(() => null),
        fetch(`${API_URL}/api/cloud/jobs`, { signal: controller.signal }).catch(() => null),
        fetch(`${API_URL}/api/cloud/stats`, { signal: controller.signal }).catch(() => null)
      ]);

      clearTimeout(timeoutId);

      if (scansRes?.ok) {
        const data = await scansRes.json();
        setScans(Array.isArray(data) ? data : []);
      }

      if (cloudRes?.ok) {
        const data = await cloudRes.json();
        setCloudJobs(data.jobs || []);
      }

      if (statsRes?.ok) {
        const data = await statsRes.json();
        setCloudStats(data);
      }

      setError(null);
    } catch {
      setError("Cannot connect to backend. Please start the server.");
      setScans([]);
      setCloudJobs([]);
    } finally {
      clearTimeout(timeoutId);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Combine stats
  const totalScans = scans.length + cloudJobs.length;
  const activeScans = scans.filter((s) => s.status === "running").length +
    cloudJobs.filter((j) => j.status === "running").length;
  const storageFound = cloudStats?.storage_found || 0;
  const secretsFound = cloudStats?.secrets_found || 0;

  // Combine recent jobs
  const recentJobs = [
    ...cloudJobs.map(j => ({ ...j, source: "cloud" })),
    ...scans.map(s => ({ ...s, source: "legacy" }))
  ].sort((a, b) => {
    const dateA = new Date(a.started_at || a.timestamp || 0);
    const dateB = new Date(b.started_at || b.timestamp || 0);
    return dateB.getTime() - dateA.getTime();
  }).slice(0, 8);

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "2rem" }}>
        <h1 style={{ fontSize: "2rem", fontWeight: "700" }}>
          Dashboard
        </h1>
        <button
          onClick={fetchData}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
            padding: "0.5rem 1rem",
            background: "transparent",
            border: "1px solid var(--border-color)",
            borderRadius: "6px",
            color: "var(--text-primary)",
            cursor: "pointer"
          }}
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {/* Connection Error Banner */}
      {error && (
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "1rem",
          padding: "1rem 1.5rem",
          marginBottom: "1.5rem",
          background: "rgba(239, 68, 68, 0.1)",
          border: "1px solid rgba(239, 68, 68, 0.3)",
          borderRadius: "8px",
          color: "#ef4444"
        }}>
          <WifiOff size={24} />
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: "600" }}>Backend Not Connected</div>
            <div style={{ fontSize: "0.9rem", opacity: 0.9 }}>
              Start with: <code style={{ background: "rgba(0,0,0,0.2)", padding: "2px 6px", borderRadius: "4px" }}>./cloud-asf dashboard</code>
            </div>
          </div>
          <button
            onClick={fetchData}
            style={{
              padding: "0.5rem 1rem",
              background: "rgba(239, 68, 68, 0.2)",
              border: "1px solid rgba(239, 68, 68, 0.4)",
              borderRadius: "6px",
              color: "#ef4444",
              cursor: "pointer"
            }}
          >
            Retry
          </button>
        </div>
      )}

      {/* Stats Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "1.5rem", marginBottom: "3rem" }}>
        <StatCard title="Total Scans" value={totalScans} icon={Shield} />
        <StatCard title="Active Scans" value={activeScans} icon={Activity} trend={activeScans > 0 ? "Running" : undefined} />
        <StatCard title="Storage Found" value={storageFound} icon={Database} />
        <StatCard title="Secrets Found" value={secretsFound} icon={Key} trendType={secretsFound > 0 ? "negative" : undefined} />
      </div>

      {/* Quick Actions */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1rem", marginBottom: "2rem" }}>
        <Link href="/scan/new" className="glass-card" style={{
          padding: "1.5rem",
          display: "flex",
          alignItems: "center",
          gap: "1rem",
          textDecoration: "none"
        }}>
          <div style={{
            width: "48px", height: "48px", borderRadius: "12px",
            background: "linear-gradient(135deg, var(--accent-primary), #0088ff)",
            display: "flex", alignItems: "center", justifyContent: "center"
          }}>
            <Shield size={24} color="black" />
          </div>
          <div>
            <h3 style={{ fontWeight: "600", color: "white" }}>New Scan</h3>
            <p style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>Start cloud reconnaissance</p>
          </div>
        </Link>

        <Link href="/cloud" className="glass-card" style={{
          padding: "1.5rem",
          display: "flex",
          alignItems: "center",
          gap: "1rem",
          textDecoration: "none"
        }}>
          <div style={{
            width: "48px", height: "48px", borderRadius: "12px",
            background: "linear-gradient(135deg, #7000ff, #00f2ff)",
            display: "flex", alignItems: "center", justifyContent: "center"
          }}>
            <Cloud size={24} color="white" />
          </div>
          <div>
            <h3 style={{ fontWeight: "600", color: "white" }}>Cloud Recon</h3>
            <p style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>AWS, Azure, GCP scanning</p>
          </div>
        </Link>

        <Link href="/scan/history" className="glass-card" style={{
          padding: "1.5rem",
          display: "flex",
          alignItems: "center",
          gap: "1rem",
          textDecoration: "none"
        }}>
          <div style={{
            width: "48px", height: "48px", borderRadius: "12px",
            background: "linear-gradient(135deg, #00ff9d, #00f2ff)",
            display: "flex", alignItems: "center", justifyContent: "center"
          }}>
            <Bug size={24} color="black" />
          </div>
          <div>
            <h3 style={{ fontWeight: "600", color: "white" }}>View Results</h3>
            <p style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>Browse scan history</p>
          </div>
        </Link>
      </div>

      {/* Recent Activity */}
      <div className="glass-card" style={{ padding: "1.5rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "1.5rem" }}>
          <h2 style={{ fontSize: "1.25rem", fontWeight: "600" }}>Recent Activity</h2>
          <Link href="/scan/history" style={{ color: "var(--accent-primary)", fontWeight: "600" }}>
            View All →
          </Link>
        </div>

        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left", color: "var(--text-secondary)", borderBottom: "1px solid var(--border-color)" }}>
              <th style={{ padding: "1rem 0" }}>Target</th>
              <th>Type</th>
              <th>Status</th>
              <th>Date</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} style={{ padding: "2rem", textAlign: "center" }}>Loading...</td></tr>
            ) : recentJobs.length === 0 ? (
              <tr><td colSpan={5} style={{ padding: "2rem", textAlign: "center", color: "var(--text-muted)" }}>
                {error ? "Connect to backend to view scans" : "No scans found. Start one!"}
              </td></tr>
            ) : (
              recentJobs.map((job) => {
                const isCloud = job.source === "cloud";
                const link = isCloud ? `/cloud/${job.id}` : `/scan/${job.id}`;

                return (
                  <tr key={job.id} style={{ borderBottom: "1px solid var(--border-color)" }}>
                    <td style={{ padding: "1rem 0", fontWeight: "500" }}>
                      {job.target || job.keyword || job.name || "Untitled"}
                    </td>
                    <td style={{ textTransform: "capitalize", color: "var(--text-secondary)" }}>
                      {(job.type || "scan").replace("_", " ")}
                    </td>
                    <td>
                      <span style={{
                        padding: "0.25rem 0.75rem",
                        borderRadius: "20px",
                        fontSize: "0.85rem",
                        background: job.status === "completed" ? "rgba(0, 255, 157, 0.1)" :
                          job.status === "running" ? "rgba(0, 242, 255, 0.1)" : "rgba(255, 0, 85, 0.1)",
                        color: job.status === "completed" ? "var(--accent-success)" :
                          job.status === "running" ? "var(--accent-primary)" : "var(--accent-danger)"
                      }}>
                        {job.status}
                      </span>
                    </td>
                    <td style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>
                      {new Date(job.started_at || job.timestamp || "").toLocaleString()}
                    </td>
                    <td>
                      <Link href={link} style={{ color: "var(--accent-primary)", fontSize: "0.9rem" }}>
                        View →
                      </Link>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
