"use client";

import { useEffect, useState } from "react";
import {
  Settings, Save, Eye, EyeOff, Key, Cloud, Shield,
  CheckCircle, AlertTriangle, Loader2, RefreshCw
} from "lucide-react";

const API_URL = "http://localhost:8000";

interface CloudSettings {
  aws_access_key_id?: string;
  aws_secret_access_key?: string;
  aws_default_region?: string;
  azure_client_id?: string;
  azure_client_secret?: string;
  azure_tenant_id?: string;
  azure_subscription_id?: string;
  google_application_credentials?: string;
  gemini_api_key?: string;
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<CloudSettings>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/api/settings`);
      if (res.ok) {
        const data = await res.json();
        setSettings(data || {});
      }
    } catch (err) {
      console.error("Failed to fetch settings", err);
    } finally {
      setLoading(false);
    }
  };

  const saveSettings = async () => {
    setSaving(true);
    setMessage(null);
    try {
      const res = await fetch(`${API_URL}/api/settings`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings)
      });

      if (res.ok) {
        setMessage({ type: "success", text: "Settings saved successfully!" });
        fetchSettings(); // Refresh to get masked values
      } else {
        setMessage({ type: "error", text: "Failed to save settings" });
      }
    } catch (err) {
      setMessage({ type: "error", text: "Cannot connect to backend" });
    } finally {
      setSaving(false);
    }
  };

  const toggleShowSecret = (key: string) => {
    setShowSecrets(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const updateField = (key: keyof CloudSettings, value: string) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  if (loading) {
    return (
      <div style={{ textAlign: "center", padding: "4rem", color: "var(--text-muted)" }}>
        <Loader2 size={32} className="animate-spin" />
        <p style={{ marginTop: "1rem" }}>Loading settings...</p>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: "900px", margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "2rem" }}>
        <div>
          <h1 style={{ fontSize: "2rem", fontWeight: "700", display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <Settings size={28} />
            Settings
          </h1>
          <p style={{ color: "var(--text-secondary)", marginTop: "0.5rem" }}>
            Configure cloud provider credentials and API keys
          </p>
        </div>
        <button
          onClick={saveSettings}
          disabled={saving}
          style={{
            display: "flex", alignItems: "center", gap: "0.5rem",
            padding: "0.75rem 1.5rem",
            background: saving ? "#333" : "linear-gradient(135deg, var(--accent-primary), #0088ff)",
            border: "none", borderRadius: "8px",
            color: saving ? "var(--text-muted)" : "black",
            fontWeight: "600", cursor: saving ? "not-allowed" : "pointer"
          }}
        >
          {saving ? <Loader2 size={18} className="animate-spin" /> : <Save size={18} />}
          {saving ? "Saving..." : "Save Settings"}
        </button>
      </div>

      {/* Message */}
      {message && (
        <div style={{
          display: "flex", alignItems: "center", gap: "0.75rem",
          padding: "1rem", marginBottom: "1.5rem", borderRadius: "8px",
          background: message.type === "success" ? "rgba(0, 255, 157, 0.1)" : "rgba(255, 0, 85, 0.1)",
          border: `1px solid ${message.type === "success" ? "var(--accent-success)" : "var(--accent-danger)"}`,
          color: message.type === "success" ? "var(--accent-success)" : "var(--accent-danger)"
        }}>
          {message.type === "success" ? <CheckCircle size={20} /> : <AlertTriangle size={20} />}
          {message.text}
        </div>
      )}

      {/* AWS Section */}
      <div className="glass-card" style={{ padding: "1.5rem", marginBottom: "1.5rem" }}>
        <h2 style={{ fontSize: "1.25rem", fontWeight: "600", marginBottom: "1.5rem", display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <Cloud size={22} style={{ color: "#ff9900" }} />
          AWS Credentials
        </h2>

        <div style={{ display: "grid", gap: "1.25rem" }}>
          <SecretInput
            label="Access Key ID"
            value={settings.aws_access_key_id || ""}
            onChange={(v) => updateField("aws_access_key_id", v)}
            placeholder="AKIAIOSFODNN7EXAMPLE"
            show={showSecrets.aws_access_key_id}
            onToggle={() => toggleShowSecret("aws_access_key_id")}
          />
          <SecretInput
            label="Secret Access Key"
            value={settings.aws_secret_access_key || ""}
            onChange={(v) => updateField("aws_secret_access_key", v)}
            placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            show={showSecrets.aws_secret_access_key}
            onToggle={() => toggleShowSecret("aws_secret_access_key")}
            isSecret
          />
          <div>
            <label style={{ display: "block", marginBottom: "0.5rem", color: "var(--text-secondary)", fontSize: "0.9rem" }}>
              Default Region
            </label>
            <select
              value={settings.aws_default_region || ""}
              onChange={(e) => updateField("aws_default_region", e.target.value)}
              style={{
                width: "100%", padding: "0.75rem",
                background: "rgba(0,0,0,0.3)", border: "1px solid var(--border-color)",
                borderRadius: "8px", color: "white"
              }}
            >
              <option value="">Select region...</option>
              <option value="us-east-1">US East (N. Virginia)</option>
              <option value="us-west-2">US West (Oregon)</option>
              <option value="eu-west-1">EU (Ireland)</option>
              <option value="eu-central-1">EU (Frankfurt)</option>
              <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
              <option value="ap-northeast-1">Asia Pacific (Tokyo)</option>
            </select>
          </div>
        </div>
      </div>

      {/* Azure Section */}
      <div className="glass-card" style={{ padding: "1.5rem", marginBottom: "1.5rem" }}>
        <h2 style={{ fontSize: "1.25rem", fontWeight: "600", marginBottom: "1.5rem", display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <Cloud size={22} style={{ color: "#0078d4" }} />
          Azure Credentials
        </h2>

        <div style={{ display: "grid", gap: "1.25rem" }}>
          <SecretInput
            label="Client ID"
            value={settings.azure_client_id || ""}
            onChange={(v) => updateField("azure_client_id", v)}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            show={showSecrets.azure_client_id}
            onToggle={() => toggleShowSecret("azure_client_id")}
          />
          <SecretInput
            label="Client Secret"
            value={settings.azure_client_secret || ""}
            onChange={(v) => updateField("azure_client_secret", v)}
            placeholder="Enter client secret"
            show={showSecrets.azure_client_secret}
            onToggle={() => toggleShowSecret("azure_client_secret")}
            isSecret
          />
          <SecretInput
            label="Tenant ID"
            value={settings.azure_tenant_id || ""}
            onChange={(v) => updateField("azure_tenant_id", v)}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            show={showSecrets.azure_tenant_id}
            onToggle={() => toggleShowSecret("azure_tenant_id")}
          />
          <SecretInput
            label="Subscription ID"
            value={settings.azure_subscription_id || ""}
            onChange={(v) => updateField("azure_subscription_id", v)}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            show={showSecrets.azure_subscription_id}
            onToggle={() => toggleShowSecret("azure_subscription_id")}
          />
        </div>
      </div>

      {/* GCP Section */}
      <div className="glass-card" style={{ padding: "1.5rem", marginBottom: "1.5rem" }}>
        <h2 style={{ fontSize: "1.25rem", fontWeight: "600", marginBottom: "1.5rem", display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <Cloud size={22} style={{ color: "#4285f4" }} />
          Google Cloud Credentials
        </h2>

        <SecretInput
          label="Service Account Key Path"
          value={settings.google_application_credentials || ""}
          onChange={(v) => updateField("google_application_credentials", v)}
          placeholder="/path/to/service-account.json"
          show={showSecrets.google_application_credentials}
          onToggle={() => toggleShowSecret("google_application_credentials")}
        />
      </div>

      {/* AI Section */}
      <div className="glass-card" style={{ padding: "1.5rem" }}>
        <h2 style={{ fontSize: "1.25rem", fontWeight: "600", marginBottom: "1.5rem", display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <Key size={22} style={{ color: "var(--accent-secondary)" }} />
          AI Configuration
        </h2>

        <SecretInput
          label="Gemini API Key"
          value={settings.gemini_api_key || ""}
          onChange={(v) => updateField("gemini_api_key", v)}
          placeholder="Enter your Gemini API key"
          show={showSecrets.gemini_api_key}
          onToggle={() => toggleShowSecret("gemini_api_key")}
          isSecret
        />
        <p style={{ marginTop: "0.75rem", fontSize: "0.85rem", color: "var(--text-muted)" }}>
          Used for AI-powered vulnerability analysis and report generation.
          Get a key at <a href="https://aistudio.google.com/" target="_blank" rel="noopener" style={{ color: "var(--accent-primary)" }}>Google AI Studio</a>
        </p>
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

interface SecretInputProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  show: boolean;
  onToggle: () => void;
  isSecret?: boolean;
}

function SecretInput({ label, value, onChange, placeholder, show, onToggle, isSecret = false }: SecretInputProps) {
  const isMasked = value && value.includes("***");

  return (
    <div>
      <label style={{ display: "block", marginBottom: "0.5rem", color: "var(--text-secondary)", fontSize: "0.9rem" }}>
        {label}
      </label>
      <div style={{ position: "relative" }}>
        <input
          type={show || !isSecret ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          style={{
            width: "100%", padding: "0.75rem",
            paddingRight: "3rem",
            background: "rgba(0,0,0,0.3)", border: "1px solid var(--border-color)",
            borderRadius: "8px", color: isMasked ? "var(--text-muted)" : "white",
            fontFamily: "monospace"
          }}
        />
        {isSecret && (
          <button
            type="button"
            onClick={onToggle}
            style={{
              position: "absolute", right: "0.75rem", top: "50%",
              transform: "translateY(-50%)",
              background: "transparent", border: "none",
              color: "var(--text-muted)", cursor: "pointer"
            }}
          >
            {show ? <EyeOff size={18} /> : <Eye size={18} />}
          </button>
        )}
      </div>
    </div>
  );
}
