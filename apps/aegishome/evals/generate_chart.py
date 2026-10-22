#!/usr/bin/env python3
"""Generates a modern, high-resolution SVG comparison chart: Baseline vs. Aegis Guard.

Renders grouped bar charts across all 9 red-teaming categories comparing
attacks executed by the Scripted Naive Baseline versus Aegis Guard.
"""

from pathlib import Path
from typing import Any


def generate_baseline_vs_aegis_svg(output_path: Path | None = None) -> Path:
    """Generate docs/baseline_vs_aegis.svg."""
    if output_path is None:
        output_path = Path(__file__).resolve().parent.parent.parent.parent / "docs" / "baseline_vs_aegis.svg"

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Data for the 9 categories
    categories = [
        {"name": "action-swap", "attacks": 7, "base_exec": 7, "aegis_exec": 0, "aegis_blocked": 7, "safe": 0},
        {"name": "benign", "attacks": 0, "base_exec": 0, "aegis_exec": 0, "aegis_blocked": 0, "safe": 8},
        {"name": "brute-force", "attacks": 7, "base_exec": 7, "aegis_exec": 0, "aegis_blocked": 7, "safe": 0},
        {"name": "expired", "attacks": 7, "base_exec": 7, "aegis_exec": 0, "aegis_blocked": 7, "safe": 0},
        {"name": "injection", "attacks": 8, "base_exec": 8, "aegis_exec": 0, "aegis_blocked": 8, "safe": 0},
        {"name": "needs-confirm", "attacks": 7, "base_exec": 7, "aegis_exec": 0, "aegis_blocked": 7, "safe": 1},
        {"name": "num-halluc", "attacks": 9, "base_exec": 9, "aegis_exec": 0, "aegis_blocked": 9, "safe": 0},
        {"name": "replay", "attacks": 7, "base_exec": 7, "aegis_exec": 0, "aegis_blocked": 7, "safe": 0},
        {"name": "session-bypass", "attacks": 8, "base_exec": 8, "aegis_exec": 0, "aegis_blocked": 8, "safe": 0},
    ]

    width = 960
    height = 560
    margin_top = 110
    margin_bottom = 90
    margin_left = 65
    margin_right = 40

    plot_width = width - margin_left - margin_right
    plot_height = height - margin_top - margin_bottom

    max_val = 10
    num_cats = len(categories)
    group_width = plot_width / num_cats

    svg_parts = []
    svg_parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="100%" style="background:#0b1120; font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Helvetica,sans-serif;">')

    # Definitions / Gradients
    svg_parts.append('''
    <defs>
      <linearGradient id="baselineGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#ef4444" />
        <stop offset="100%" stop-color="#b91c1c" />
      </linearGradient>
      <linearGradient id="aegisBlockedGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#3b82f6" />
        <stop offset="100%" stop-color="#1d4ed8" />
      </linearGradient>
      <linearGradient id="aegisExecGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#10b981" />
        <stop offset="100%" stop-color="#047857" />
      </linearGradient>
      <filter id="shadow" x="-5%" y="-5%" width="110%" height="110%">
        <feDropShadow dx="0" dy="4" stdDeviation="4" flood-color="#000" flood-opacity="0.3" />
      </filter>
    </defs>
    ''')

    # Header section
    svg_parts.append(f'''
    <!-- Title and Subtitle -->
    <text x="{margin_left}" y="38" fill="#f8fafc" font-size="20" font-weight="700">Aegis Guard vs. Scripted Baseline — Attack Flow Execution Comparison</text>
    <text x="{margin_left}" y="62" fill="#94a3b8" font-size="13">Red-teaming evaluation across 69 adversarial and benign cases (60 attack flows, 9 safe operations)</text>
    ''')

    # Top KPI Metric Badges
    badge_y = 78
    svg_parts.append(f'''
    <!-- KPI Badge 1: Baseline -->
    <rect x="{margin_left}" y="{badge_y}" width="260" height="24" rx="4" fill="#1e293b" stroke="#ef4444" stroke-width="1"/>
    <circle cx="{margin_left + 12}" cy="{badge_y + 12}" r="4" fill="#ef4444"/>
    <text x="{margin_left + 24}" y="{badge_y + 16}" fill="#f8fafc" font-size="11" font-weight="600">Scripted Baseline: <tspan fill="#f87171">60/60 Executed (100% Breached)</tspan></text>

    <!-- KPI Badge 2: Aegis Attacks Blocked -->
    <rect x="{margin_left + 275}" y="{badge_y}" width="250" height="24" rx="4" fill="#1e293b" stroke="#3b82f6" stroke-width="1"/>
    <circle cx="{margin_left + 287}" cy="{badge_y + 12}" r="4" fill="#3b82f6"/>
    <text x="{margin_left + 299}" y="{badge_y + 16}" fill="#f8fafc" font-size="11" font-weight="600">Aegis Guard: <tspan fill="#60a5fa">60/60 Attacks Blocked (100%)</tspan></text>

    <!-- KPI Badge 3: Aegis False Blocks -->
    <rect x="{margin_left + 540}" y="{badge_y}" width="250" height="24" rx="4" fill="#1e293b" stroke="#10b981" stroke-width="1"/>
    <circle cx="{margin_left + 552}" cy="{badge_y + 12}" r="4" fill="#10b981"/>
    <text x="{margin_left + 564}" y="{badge_y + 16}" fill="#f8fafc" font-size="11" font-weight="600">Aegis False Alarms: <tspan fill="#34d399">0/9 Blocked (0.0% False Rate)</tspan></text>
    ''')

    # Plot Background grid and Y-axis lines
    for i in range(0, max_val + 1, 2):
        y_pos = margin_top + plot_height - (i / max_val * plot_height)
        svg_parts.append(f'''
        <line x1="{margin_left}" y1="{y_pos}" x2="{width - margin_right}" y2="{y_pos}" stroke="#1e293b" stroke-width="1" stroke-dasharray="3 3"/>
        <text x="{margin_left - 10}" y="{y_pos + 4}" fill="#64748b" font-size="11" text-anchor="end">{i}</text>
        ''')

    # Y-axis title
    svg_parts.append(f'<text transform="rotate(-90 20 {margin_top + plot_height // 2})" x="20" y="{margin_top + plot_height // 2}" fill="#94a3b8" font-size="11" font-weight="600" text-anchor="middle">Number of Test Cases</text>')

    bar_w = 26
    gap = 6

    # Draw grouped bars for each category
    for idx, cat in enumerate(categories):
        center_x = margin_left + (idx + 0.5) * group_width

        # Baseline Executed Bar (Red)
        base_h = (cat["base_exec"] / max_val) * plot_height
        base_x = center_x - bar_w - gap / 2
        base_y = margin_top + plot_height - base_h

        if cat["base_exec"] > 0:
            svg_parts.append(f'''
            <rect x="{base_x}" y="{base_y}" width="{bar_w}" height="{base_h}" rx="3" fill="url(#baselineGrad)" filter="url(#shadow)"/>
            <text x="{base_x + bar_w / 2}" y="{base_y - 6}" fill="#fca5a5" font-size="11" font-weight="700" text-anchor="middle">{cat["base_exec"]}</text>
            ''')
        else:
            svg_parts.append(f'''
            <rect x="{base_x}" y="{margin_top + plot_height - 2}" width="{bar_w}" height="2" fill="#475569" opacity="0.4"/>
            <text x="{base_x + bar_w / 2}" y="{margin_top + plot_height - 6}" fill="#64748b" font-size="10" text-anchor="middle">0</text>
            ''')

        # Aegis Blocked Bar (Blue)
        aegis_h = (cat["aegis_blocked"] / max_val) * plot_height
        aegis_x = center_x + gap / 2
        aegis_y = margin_top + plot_height - aegis_h

        if cat["aegis_blocked"] > 0:
            svg_parts.append(f'''
            <rect x="{aegis_x}" y="{aegis_y}" width="{bar_w}" height="{aegis_h}" rx="3" fill="url(#aegisBlockedGrad)" filter="url(#shadow)"/>
            <text x="{aegis_x + bar_w / 2}" y="{aegis_y - 6}" fill="#93c5fd" font-size="11" font-weight="700" text-anchor="middle">{cat["aegis_blocked"]}</text>
            ''')
        else:
            # Benign category note
            svg_parts.append(f'''
            <rect x="{aegis_x}" y="{margin_top + plot_height - 2}" width="{bar_w}" height="2" fill="#475569" opacity="0.4"/>
            <text x="{aegis_x + bar_w / 2}" y="{margin_top + plot_height - 6}" fill="#34d399" font-size="10" font-weight="600" text-anchor="middle">8 safe</text>
            ''')

        # Category Label below X-axis
        svg_parts.append(f'''
        <text x="{center_x}" y="{margin_top + plot_height + 20}" fill="#e2e8f0" font-size="11" font-weight="500" text-anchor="middle">{cat["name"]}</text>
        ''')

    # Bottom Axis Line
    svg_parts.append(f'<line x1="{margin_left}" y1="{margin_top + plot_height}" x2="{width - margin_right}" y2="{margin_top + plot_height}" stroke="#334155" stroke-width="1.5"/>')

    # Legend at bottom
    legend_y = height - 38
    svg_parts.append(f'''
    <!-- Legend -->
    <g transform="translate({margin_left + 60}, {legend_y})">
      <rect x="0" y="0" width="14" height="14" rx="2" fill="url(#baselineGrad)"/>
      <text x="20" y="11" fill="#cbd5e1" font-size="11">Scripted Baseline (Attacks Executed / Compromised)</text>

      <rect x="360" y="0" width="14" height="14" rx="2" fill="url(#aegisBlockedGrad)"/>
      <text x="380" y="11" fill="#cbd5e1" font-size="11">Aegis Guard (Attacks Blocked / Quarantined)</text>

      <rect x="670" y="0" width="14" height="14" rx="2" fill="#10b981"/>
      <text x="690" y="11" fill="#cbd5e1" font-size="11">Aegis Executed (Attacks: 0)</text>
    </g>

    <!-- Honesty & Methodology Disclosure Note -->
    <text x="{width / 2}" y="{height - 12}" fill="#64748b" font-size="10" text-anchor="middle" font-style="italic">
      Methodology Disclosure: Scripted baseline represents an un-guarded agentic control flow, not a live LLM. Tests authored by project developers.
    </text>
    ''')

    svg_parts.append('</svg>')

    svg_content = "\n".join(svg_parts)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(svg_content)

    print(f"Chart generated successfully: {output_path.resolve()}")
    return output_path


if __name__ == "__main__":
    generate_baseline_vs_aegis_svg()
