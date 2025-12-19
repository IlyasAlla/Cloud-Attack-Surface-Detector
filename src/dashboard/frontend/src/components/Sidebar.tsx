"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
    LayoutDashboard, Search, Cloud, History, Settings,
    Terminal, Shield, Plus
} from "lucide-react";
import styles from "./Sidebar.module.css";

const navItems = [
    { href: "/", label: "Dashboard", icon: LayoutDashboard },
    { href: "/scan/new", label: "New Scan", icon: Plus },
    { href: "/cloud", label: "Cloud Recon", icon: Cloud },
    { href: "/scan/history", label: "Scan History", icon: History },
    { href: "/settings", label: "Settings", icon: Settings },
    { href: "/system-logs", label: "System Logs", icon: Terminal },
];

export default function Sidebar() {
    const pathname = usePathname();

    const isActive = (href: string) => {
        if (href === "/") return pathname === "/";
        return pathname.startsWith(href);
    };

    return (
        <aside className={styles.sidebar}>
            {/* Logo */}
            <div className={styles.logo}>
                <Shield size={28} style={{ color: "var(--accent-primary)" }} />
                <div>
                    <span className={styles.logoText}>Cloud ASF</span>
                    <span className={styles.version}>v2.0.0</span>
                </div>
            </div>

            {/* Navigation */}
            <nav className={styles.nav}>
                {navItems.map((item) => {
                    const Icon = item.icon;
                    const active = isActive(item.href);

                    return (
                        <Link
                            key={item.href}
                            href={item.href}
                            className={`${styles.navItem} ${active ? styles.active : ""}`}
                        >
                            <Icon size={20} />
                            <span>{item.label}</span>
                        </Link>
                    );
                })}
            </nav>

            {/* Footer */}
            <div className={styles.footer}>
                <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                    Attack Surface Edition
                </p>
            </div>
        </aside>
    );
}
