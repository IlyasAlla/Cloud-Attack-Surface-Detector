import { useEffect, useState } from "react";
import { CheckCircle, XCircle, Info, X } from "lucide-react";

export type ToastType = "success" | "error" | "info";

interface ToastProps {
    message: string;
    type: ToastType;
    onClose: () => void;
    duration?: number;
}

export default function Toast({ message, type, onClose, duration = 3000 }: ToastProps) {
    const [isVisible, setIsVisible] = useState(true);

    useEffect(() => {
        const timer = setTimeout(() => {
            setIsVisible(false);
            setTimeout(onClose, 300); // Wait for animation
        }, duration);

        return () => clearTimeout(timer);
    }, [duration, onClose]);

    const bgColors = {
        success: "rgba(0, 255, 157, 0.1)",
        error: "rgba(255, 0, 85, 0.1)",
        info: "rgba(0, 242, 255, 0.1)"
    };

    const borderColors = {
        success: "var(--accent-success)",
        error: "var(--accent-danger)",
        info: "var(--accent-primary)"
    };

    const icons = {
        success: <CheckCircle size={20} color="var(--accent-success)" />,
        error: <XCircle size={20} color="var(--accent-danger)" />,
        info: <Info size={20} color="var(--accent-primary)" />
    };

    if (!isVisible) return null;

    return (
        <div style={{
            position: "fixed", bottom: "2rem", right: "2rem",
            background: "rgba(10, 10, 15, 0.95)", backdropFilter: "blur(10px)",
            border: `1px solid ${borderColors[type]}`, borderLeftWidth: "4px",
            borderRadius: "8px", padding: "1rem 1.5rem",
            display: "flex", alignItems: "center", gap: "1rem",
            boxShadow: "0 10px 30px rgba(0,0,0,0.5)",
            zIndex: 9999, animation: "slideIn 0.3s ease-out",
            minWidth: "300px"
        }}>
            {icons[type]}
            <div style={{ flex: 1, color: "white", fontSize: "0.9rem" }}>{message}</div>
            <button
                onClick={() => { setIsVisible(false); setTimeout(onClose, 300); }}
                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-secondary)" }}
            >
                <X size={16} />
            </button>
            <style jsx>{`
                @keyframes slideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
            `}</style>
        </div>
    );
}
