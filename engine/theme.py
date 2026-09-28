"""Visual system for the ECDAT console.

WHY A SEPARATE MODULE
---------------------
`app.py` is already a thousand lines of analysis decisions; burying a stylesheet inside it made
the design impossible to review and impossible to test. This module holds the CSS and the few
pure-HTML component builders, so both can be asserted on without a running Streamlit server --
the same constraint `gui_helpers.py` already works under. NOTHING HERE IMPORTS STREAMLIT and
nothing here opens a socket.

THE AESTHETIC: "laboratory instrument", not "security dashboard"
----------------------------------------------------------------
Most crypto tooling looks like a wall of coloured pills. The idea here is a bench instrument: a
dark chassis, phosphor readouts, hairline rules, and every datum set in a monospace so figures
align in a column and can be compared by eye. Two deliberate consequences:

*   **Uncertainty is drawn, not merely written.** A headline figure is never rendered without its
    qualifier on the same surface -- `12 findings` never appears alone, it appears with `3 proven
    use`. A console that draws its own uncertainty is the visual form of the tool's whole thesis.
*   **Motion is instrumentation, not decoration.** Nothing pulses to look alive. The only
    animation permitted to run unattended is the scanning pulse, and it is simply not rendered
    once a result exists. A tool whose job is to report *not knowing* should not fidget.

ORIGINALITY
-----------
Written for this project. The palette, the type pairing, the grid and every component below were
authored here; no stylesheet, markup or design token was taken from another project. Where
competitor research informed *what to show* -- an explicit sensor-status panel, an assurance tier
that is not the same thing as confidence -- that is an idea, and ideas are attributed in
`research/competitive/ANALYSIS.md` rather than copied as code.

The type pairing is "Instrument Serif" against "IBM Plex Mono": a high-contrast editorial serif
for headings over a technical monospace for every number, chosen because this console is a report
that happens to be interactive. Both degrade to the platform stack when the network is
unavailable, because a tool that must run air-gapped still has to be legible offline.
"""

from engine.gui_helpers import escape

CSS = """
<style>
/* ---- tokens -------------------------------------------------------------------------------
   NO @import, ON PURPOSE.

   An earlier version of this stylesheet began with an `@import` of Google Fonts. That was a real
   network request on every page load, and it silently broke a claim this project makes in three
   places and treats as a product guarantee: "Everything renders offline: no CDN, no network
   call, no telemetry." A security tool that phones a font CDN the moment an analyst opens it
   is leaking the fact that they are analysing cryptography, and it cannot be used in an
   air-gapped review at all.

   So the type stack is declared as a LOCAL font list with a solid generic fallback, and the
   pairing degrades rather than blocking. Instrument Serif and IBM Plex Mono are named first
   because they are what the design was drawn around; on a machine without them the console
   falls back to the platform serif and monospace and loses only the character, never legibility
   or a single bit of function.
   ------------------------------------------------------------------------------------------ */
:root {
  --chassis:     #0d1014;   /* the bench the instrument sits on */
  --panel:       #141920;   /* raised surface, one step up from the chassis */
  --panel-edge:  #212934;   /* hairline. Always 1px, never a heavy border. */
  --ink:         #e8edf2;   /* primary text */
  --ink-dim:     #93a1b0;   /* secondary text, still AA on --panel */
  --ink-faint:   #5d6b7a;   /* axis labels. Never carries meaning on its own. */

  --signal-ok:   #3fb98c;   /* proven / satisfied */
  --signal-warn: #d9a441;   /* attention */
  --signal-bad:  #e5604d;   /* broken / critical */
  --signal-info: #5aa9e6;   /* informational, capability tier */
  --signal-idle: #4a5563;   /* not run, unknown */

  --chassis-1: #141920;  --chassis-2: #1b222b;  --chassis-3: #232c37;
  --chassis-4: #2e3946;  --chassis-5: #3b4859;

  --mono: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --display: 'Instrument Serif', Georgia, 'Times New Roman', serif;
}

.stApp { background: var(--chassis); }

/* A very low-opacity scanline wash. It reads as a CRT bezel without impairing text contrast,
   and it is the only texture in the system -- no glassmorphism, no drop-shadow theatre. */
.stApp::before {
  content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background: repeating-linear-gradient(180deg, rgba(255,255,255,.014) 0 1px, transparent 1px 3px);
}

/* ---- typography ---------------------------------------------------------------------------- */
h1, h2, h3, h4 { font-family: var(--display) !important; font-weight: 400 !important;
                 letter-spacing: -0.015em; color: var(--ink); }
h1 { font-size: 2.6rem !important; line-height: 1.05 !important; }
h2 { font-size: 1.9rem !important; }
h3 { font-size: 1.4rem !important; }
h4 { font-size: 1.12rem !important; }
p, li, span, label { color: var(--ink); }
.ecdat-sub, [data-testid="stCaptionContainer"] p {
  color: var(--ink-dim) !important; font-family: var(--mono); font-size: 0.82rem !important;
}

/* Every number is monospaced and tabular, so a column of figures aligns and a reviewer can compare
   magnitudes without reading the labels. */
.ecdat-mono, code, pre, [data-testid="stMetricValue"] {
  font-family: var(--mono) !important;
  font-variant-numeric: tabular-nums; font-feature-settings: 'tnum' 1;
}
[data-testid="stMetricValue"] { font-size: 1.75rem !important; color: var(--ink) !important;
                                font-weight: 500 !important; }
div[data-testid="stMetricLabel"] p { font-size: 0.72rem !important; text-transform: uppercase;
                                    letter-spacing: 0.09em; color: var(--ink-faint) !important; }
[data-testid="stMetricDelta"] { font-family: var(--mono); font-size: 0.78rem; }

/* ---- surfaces ------------------------------------------------------------------------------ */
div[data-testid="stVerticalBlockBorderWrapper"] > div,
div[data-testid="stExpander"] {
  background: var(--panel); border: 1px solid var(--panel-edge) !important;
  border-radius: 3px !important;              /* near-square: an instrument, not a phone app */
}
[data-testid="stSidebar"] { background: #0a0d11; border-right: 1px solid var(--panel-edge); }
[data-testid="stSidebar"] .stButton button { width: 100%; }

/* ---- buttons -------------------------------------------------------------------------------- */
.stButton button, .stDownloadButton button {
  background: var(--chassis-3); color: var(--ink); border: 1px solid var(--chassis-5);
  border-radius: 2px; font-family: var(--mono); font-size: 0.8rem; letter-spacing: 0.06em;
  text-transform: uppercase; padding: 0.5rem 0.9rem;
  transition: background .14s ease, border-color .14s ease, transform .08s ease;
}
.stButton button:hover, .stDownloadButton button:hover {
  background: var(--chassis-4); border-color: var(--signal-info); color: #fff;
}
.stButton button:active { transform: translateY(1px); }
.stButton button[kind="primary"] {
  background: var(--signal-info); border-color: var(--signal-info); color: #06121c; font-weight: 600;
}
.stButton button[kind="primary"]:hover { background: #78bdf0; border-color: #78bdf0; color: #06121c; }
.stButton button:focus-visible { outline: 2px solid var(--signal-info); outline-offset: 2px; }

/* ---- inputs --------------------------------------------------------------------------------- */
[data-baseweb="select"] > div, .stTextInput input, [data-baseweb="input"] > div {
  background: var(--chassis-1) !important; border-color: var(--chassis-4) !important;
  border-radius: 2px !important; font-family: var(--mono); font-size: 0.85rem;
}
input[type="range"] { accent-color: var(--signal-info); }

/* ---- data tables: the densest screen in the tool, so it gets the most care --------------------- */
[data-testid="stDataFrame"] { border: 1px solid var(--panel-edge); border-radius: 3px; }
[data-testid="stDataFrame"] * { font-family: var(--mono) !important; font-size: 0.78rem !important;
                                font-variant-numeric: tabular-nums; }
[data-testid="stDataFrame"] [role="columnheader"] {
  background: var(--chassis-2) !important; color: var(--ink-dim) !important;
  text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.68rem !important;
  border-bottom: 1px solid var(--panel-edge) !important;
}
[data-testid="stDataFrame"] [role="gridcell"] { border-bottom: 1px solid #171d25 !important; }

/* ---- tabs are the console's primary navigation, so they read as instrument labels -------------- */
[data-baseweb="tab-list"] { gap: 2px; border-bottom: 1px solid var(--panel-edge); }
[data-baseweb="tab"] { font-family: var(--mono); font-size: 0.78rem; letter-spacing: 0.05em;
                       text-transform: uppercase; color: var(--ink-dim); padding: 0.5rem 0.85rem;
                       background: transparent; border: none; border-bottom: 2px solid transparent; }
[data-baseweb="tab"]:hover { color: var(--ink); background: var(--chassis-1); }
[data-baseweb="tab"][aria-selected="true"] { color: var(--signal-info);
                                             border-bottom-color: var(--signal-info); }

/* ---- base for the primitives defined in app.py and gui_helpers -------------------------------- */
.ecdat-chip { display:inline-block; padding:1px 9px; border-radius:2px; font-size:0.72rem;
              font-weight:600; letter-spacing:0.04em; font-family:var(--mono);
              text-transform:uppercase; border:1px solid rgba(255,255,255,.12); }
.ecdat-title { font-family: var(--display); font-size:1.6rem; line-height:1.15; margin:0; }
.ecdat-mono { font-family: var(--mono); font-variant-numeric: tabular-nums; }
.ecdat-foot { font-family: var(--mono); font-size: 0.76rem; color: var(--ink-faint); }
hr, [data-testid="stDivider"] { border-color: var(--panel-edge) !important; }

/* ---- motion ---------------------------------------------------------------------------------
   Two rules govern every animation in this file.
   1. Entrance reveals run ONCE, staggered, on load only. A result that re-animates on every
      Streamlit rerun reads as unreliable, which is the opposite of this tool's thesis.
   2. The scanning pulse is the only animation allowed to run unattended, and it exists solely to
      say "no result exists yet". It is not rendered at all once a result exists -- a console must
      never imply it is still working when it is not. */
@keyframes ec-reveal { from { opacity: 0; transform: translateY(6px); }
                       to   { opacity: 1; transform: none; } }
.ec-reveal { animation: ec-reveal .34s cubic-bezier(.22,.61,.36,1) both; }
.ec-reveal-1 { animation-delay: .04s; } .ec-reveal-2 { animation-delay: .09s; }
.ec-reveal-3 { animation-delay: .14s; } .ec-reveal-4 { animation-delay: .19s; }

@keyframes ec-pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
.ec-scanning { animation: ec-pulse 1.15s ease-in-out infinite; color: var(--signal-info);
               font-family: var(--mono); font-size: 0.78rem; letter-spacing: .08em;
               text-transform: uppercase; }

/* ---- the proof bar: the component the whole product argues for ------------------------------
   A bar whose filled portion is the share of findings that are PROVEN USE, the remainder left
   empty. It encodes in one glance the distinction the rest of the tool argues in prose: how much
   of this estate is actually evidenced versus merely reachable. A tool reporting only a total has
   nothing to draw here, which is precisely the point. */
.ec-proof { height: 3px; background: var(--chassis-4); border-radius: 2px; overflow: hidden;
           margin-top: 6px; }
.ec-proof > i { display: block; height: 100%; background: var(--signal-ok); border-radius: 2px;
                transition: width .5s cubic-bezier(.22,.61,.36,1); }
.ec-proof-legend { display:flex; justify-content:space-between; font-family:var(--mono);
                   font-size:0.68rem; color:var(--ink-faint); margin-top:3px;
                   text-transform:uppercase; letter-spacing:.06em; }

/* Reduced motion is honoured properly. An accessibility preference is not a suggestion. */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important;
                            animation-iteration-count: 1 !important;
                            transition-duration: .001ms !important; }
}
</style>
"""


# ===========================================================================================
# Components.
#
# These are pure functions returning HTML strings, for the same reason the CSS lives here: a
# design decision that can only be checked by launching a server cannot be reviewed, and a
# reviewer who cannot review it will not notice when it quietly stops telling the truth.
# ===========================================================================================

def proof_bar(proven, total, *, label="proven use", caption=None):
    """The evidence bar: the share of findings that are proven use, drawn rather than asserted.

    This is the component the whole product argues for. Every other crypto scanner can print a
    total; printing a total tells the reader nothing about how much of it is real. A filled bar
    with an empty remainder says, without prose, "this much is evidenced, this much is only
    reachable" -- which is the honest state of any static analysis.

    `total` of zero is a legitimate and important case: an unreadable tree and a clean one both
    produce zero findings, so this returns an explicit empty reading rather than a 0% bar that
    would look like good news. A 100% fill is impossible by construction unless every finding is
    proven use, which is rare and should look unusual when it happens.
    """
    proven = max(0, int(proven or 0))
    total = max(0, int(total or 0))
    if total == 0:
        return ('<div class="ec-proof" role="img" aria-label="No findings to qualify"></div>'
                '<div class="ec-proof-legend"><span>no findings</span>'
                f'<span>check the coverage manifest</span></div>')
    pct = min(100.0, 100.0 * proven / total)
    remainder = total - proven
    return (
        f'<div class="ec-proof" role="img" '
        f'aria-label="{proven} of {total} findings are proven use, {pct:.0f} percent">'
        f'<i style="width:{pct:.2f}%"></i></div>'
        f'<div class="ec-proof-legend"><span>{proven} {label}</span>'
        f'<span>{remainder} other finding{"s" if remainder != 1 else ""}</span></div>'
        + (f'<div class="ecdat-foot" style="margin-top:4px">{escape(str(caption))}</div>'
           if caption else ""))


def reveal(step=1):
    """Class for a one-shot staggered entrance. Step 0 is the base class.

    Staggering four surfaces by 50ms each reads as an instrument settling into place. The delay
    is capped by the caller: past ~4 steps the tail arrives late enough to feel broken.
    """
    return "ec-reveal" if step <= 0 else f"ec-reveal ec-reveal-{min(int(step), 4)}"


def scanning_indicator(text="scanning"):
    """The only animation allowed to run unattended, and only while no result exists."""
    return f'<span class="ec-scanning">&#9679;&nbsp; {escape(str(text))}</span>'
