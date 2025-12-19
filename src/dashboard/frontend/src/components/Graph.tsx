"use client";

import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

interface GraphProps {
    elements: any[];
    onNodeClick?: (nodeData: any) => void;
}

export default function Graph({ elements, onNodeClick }: GraphProps) {
    const containerRef = useRef<HTMLDivElement>(null);
    const cyRef = useRef<any>(null); // Use any to avoid type issues with dynamic import

    useEffect(() => {
        // SSR Check
        if (typeof window === 'undefined') return;

        let cy: any = null;

        const initGraph = async () => {
            if (!containerRef.current) return;

            try {
                // Dynamic import to ensure client-side only
                const cytoscapeModule = await import("cytoscape");
                const cytoscape = cytoscapeModule.default;

                cy = cytoscape({
                    container: containerRef.current,
                    elements: elements,
                    style: [
                        {
                            selector: 'node',
                            style: {
                                'label': 'data(label)',
                                'background-color': '#00ff9d', // Matrix Green (Safe default)
                                'color': '#fff',
                                'font-size': '12px',
                                'text-valign': 'bottom',
                                'text-margin-y': 5,
                                'width': 40,
                                'height': 40,
                                'border-width': 2,
                                'border-color': '#fff',
                                'text-outline-width': 2,
                                'text-outline-color': '#020617', // Deep Void
                                'shadow-blur': 0,
                                'shadow-color': '#00ff9d',
                                'transition-property': 'background-color, border-color, shadow-blur, opacity',
                                'transition-duration': '0.3s'
                            } as any
                        },
                        {
                            selector: 'node[vulnerable="true"]',
                            style: {
                                'background-color': '#ffaa00', // Cyber Orange (High Risk)
                                'border-color': '#ffaa00',
                                'shadow-blur': 15,
                                'shadow-color': '#ffaa00'
                            } as any
                        },
                        {
                            selector: 'node[compromised="true"]',
                            style: {
                                'background-color': '#ff0055', // Neon Red (Critical)
                                'border-color': '#ff0055',
                                'shadow-blur': 30,
                                'shadow-color': '#ff0055',
                                'width': 50,
                                'height': 50
                            } as any
                        },
                        {
                            selector: 'edge',
                            style: {
                                'width': 2,
                                'line-color': '#334155', // Faint Blue
                                'target-arrow-color': '#334155',
                                'target-arrow-shape': 'triangle',
                                'curve-style': 'bezier',
                                'opacity': 0.8,
                                'transition-property': 'opacity, line-color, width',
                                'transition-duration': '0.3s'
                            } as any
                        },
                        {
                            selector: 'edge[compromised="true"]',
                            style: {
                                'line-color': '#ff0055',
                                'target-arrow-color': '#ff0055',
                                'width': 4,
                                'line-style': 'dashed',
                                'opacity': 1
                            } as any
                        },
                        {
                            selector: '.dimmed',
                            style: {
                                'opacity': 0.1,
                                'shadow-blur': 0
                            } as any
                        },
                        {
                            selector: '.highlighted',
                            style: {
                                'opacity': 1,
                                'shadow-blur': 20,
                                'border-width': 4
                            } as any
                        }
                    ],
                    layout: {
                        name: 'cose',
                        animate: true,
                        animationDuration: 1000,
                        padding: 50,
                        randomize: true, // Explosion effect
                        componentSpacing: 100,
                        nodeRepulsion: 400000,
                        edgeElasticity: 100,
                        nestingFactor: 5
                    },
                    headless: false,
                    styleEnabled: true,
                });

                // Event Listeners
                cy.on('tap', 'node', (evt: any) => {
                    const node = evt.target;
                    if (onNodeClick) {
                        onNodeClick(node.data());
                    }
                });

                // Hover Effects
                cy.on('mouseover', 'node', (evt: any) => {
                    const node = evt.target;
                    const neighborhood = node.neighborhood().add(node);

                    cy.elements().addClass('dimmed');
                    neighborhood.removeClass('dimmed').addClass('highlighted');
                });

                cy.on('mouseout', 'node', (evt: any) => {
                    cy.elements().removeClass('dimmed').removeClass('highlighted');
                });

                cyRef.current = cy;
            } catch (error) {
                console.error("Failed to initialize graph:", error);
            }
        };

        // Small timeout to ensure DOM is ready
        const timeoutId = setTimeout(() => {
            initGraph();
        }, 100);

        return () => {
            clearTimeout(timeoutId);
            if (cy) {
                try {
                    cy.destroy();
                } catch (e) {
                    console.warn("Error destroying graph:", e);
                }
                cy = null;
                cyRef.current = null;
            }
        };
    }, [elements]);

    return (
        <div
            ref={containerRef}
            style={{
                width: "100%",
                height: "600px",
                background: "rgba(0,0,0,0.2)",
                borderRadius: "16px",
                border: "1px solid var(--border-color)"
            }}
        />
    );
}
