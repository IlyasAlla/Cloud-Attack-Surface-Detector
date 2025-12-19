import styles from "./StatCard.module.css";
import { LucideIcon } from "lucide-react";

interface StatCardProps {
    title: string;
    value: string | number;
    icon: LucideIcon;
    trend?: string;
    trendType?: "positive" | "negative";
}

export default function StatCard({ title, value, icon: Icon, trend, trendType }: StatCardProps) {
    return (
        <div className={styles.card}>
            <div className={styles.header}>
                <span>{title}</span>
                <Icon size={20} />
            </div>
            <div className={styles.value}>{value}</div>
            {trend && (
                <div className={`${styles.trend} ${styles[trendType || "positive"]}`}>
                    {trend}
                </div>
            )}
        </div>
    );
}
