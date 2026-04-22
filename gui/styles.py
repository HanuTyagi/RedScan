"""
RedScan GUI – colour palette, fonts, and widget sizing constants.
All views import from here so changes propagate everywhere.
"""

# ── Appearance ──────────────────────────────────────────────────────────────
APP_APPEARANCE = "dark"
APP_COLOR_THEME = "blue"

# ── Palette ─────────────────────────────────────────────────────────────────
BG_PRIMARY   = "#1a1a2e"
BG_SECONDARY = "#16213e"
BG_CARD      = "#0f3460"
ACCENT       = "#e94560"
ACCENT_HOVER = "#c73652"
TEXT_PRIMARY  = "#eaeaea"
TEXT_MUTED    = "#a0a0b0"
TEXT_SUCCESS  = "#2ecc71"
TEXT_WARN     = "#f39c12"
TEXT_DANGER   = "#e74c3c"

# Aggressiveness badge colours (match preset_library.AGGRESSIVENESS_COLOR)
AGG_COLORS = {
    "Low":     "#2ecc71",
    "Medium":  "#f39c12",
    "High":    "#e74c3c",
    "Extreme": "#8e44ad",
}

# ── Fonts ────────────────────────────────────────────────────────────────────
FONT_TITLE  = ("Segoe UI", 22, "bold")
FONT_H1     = ("Segoe UI", 16, "bold")
FONT_H2     = ("Segoe UI", 13, "bold")
FONT_BODY   = ("Segoe UI", 12)
FONT_SMALL  = ("Segoe UI", 10)
FONT_MONO   = ("Courier New", 11)
FONT_MONO_SM = ("Courier New", 10)

# ── Layout ───────────────────────────────────────────────────────────────────
SIDEBAR_W     = 200
WINDOW_W      = 1400
WINDOW_H      = 880
PAD           = 12
PAD_S         = 6
CARD_CORNER   = 10
BTN_CORNER    = 8
BORDER_W      = 1

# ── Sidebar nav items ────────────────────────────────────────────────────────
NAV_ITEMS = [
    ("presets",       "🎯  Preset Library"),
    ("factory",       "🔧  Command Factory"),
    ("dashboard",     "📊  Scan Dashboard"),
    ("smart_scan",    "⚡  Smart Scan"),
    ("llm",           "🤖  AI Insights"),
]
