/**
 * ttp-graph.js
 * D3 v7 fixed bipartite-column graph for TTP Overlap sections.
 *
 * Layout: actors column (left) → phase-column technique nodes (right).
 * No force simulation - positions computed once in buildLayout().
 * Node identity = phaseIndex:tech.id so duplicate T-IDs (e.g. T1219 in
 * both Initial Access and C2) render as two separate nodes, matching the
 * Grid view behavior. Do not "fix" this by deduplicating on tech.id.
 */
(function () {
  'use strict';

  // ── Guards ────────────────────────────────────────────────────────────
  if (!window.__TTP_GRAPH_DATA) return;
  var svgContainer = document.getElementById('ttp-graph-svg');
  if (!svgContainer) return;
  if (typeof d3 === 'undefined') return;

  var data   = window.__TTP_GRAPH_DATA;
  var groups = data.groups;   // [{ id, name, color }]
  var phases = data.phases;   // [{ label, techniques: [{ id, name, groups: [] }] }]
  var numGroups = groups.length;
  var numPhases = phases.length;

  // ── Layout constants ──────────────────────────────────────────────────
  var ACTOR_X       = 85;   // actor node circle center x
  var ACTOR_R       = 15;   // actor circle radius
  var TECH_R        = 5;    // technique circle radius
  var UNIV_R_EXTRA  = 4;    // extra ring radius for universal nodes
  var PHASE_START_X = 220;  // x of first technique column
  var COL_W         = 132;  // horizontal spacing between phase columns
  var PHASE_LABEL_Y = 20;   // y of phase label text
  var TECH_START_Y  = 40;   // y of first technique node in a column
  var NODE_H        = 33;   // vertical spacing between technique nodes

  // ── Render state ─────────────────────────────────────────────────────
  var rendered = false;
  var selectedActors = new Set();

  // ── D3 selection handles (populated in renderGraph) ──────────────────
  var svgEl, zoomG, edgeSel, techSel, actorSel, tooltip;

  // ── Model ─────────────────────────────────────────────────────────────
  function buildLayout() {
    var maxTechs = phases.reduce(function (m, p) {
      return Math.max(m, p.techniques.length);
    }, 0);

    var CANVAS_H = Math.max(
      TECH_START_Y + maxTechs * NODE_H + 30,
      numGroups * 60 + 40
    );
    var CANVAS_W = PHASE_START_X + numPhases * COL_W + 20;

    // Actor positions
    var actorSpacing = CANVAS_H / (numGroups + 1);
    groups.forEach(function (g, i) {
      g._x = ACTOR_X;
      g._y = actorSpacing * (i + 1);
    });

    // Technique nodes
    var techNodes = [];
    phases.forEach(function (phase, pi) {
      var colX = PHASE_START_X + pi * COL_W;
      phase.techniques.forEach(function (tech, ti) {
        var isUniversal = tech.groups.length === numGroups;
        techNodes.push({
          id:          pi + ':' + tech.id,  // per-phase identity - see file header
          techId:      tech.id,
          name:        tech.name,
          phaseLabel:  phase.label,
          phaseIndex:  pi,
          groups:      tech.groups,
          isUniversal: isUniversal,
          x:           colX,
          y:           TECH_START_Y + ti * NODE_H
        });
      });
    });

    // Links (actor → technique, one per group membership)
    var links = [];
    techNodes.forEach(function (node) {
      node.groups.forEach(function (gid) {
        var group = groups.find(function (g) { return g.id === gid; });
        if (group) {
          links.push({ source: group, target: node, color: group.color, groupId: gid });
        }
      });
    });

    return { techNodes: techNodes, links: links, CANVAS_H: CANVAS_H, CANVAS_W: CANVAS_W };
  }

  // ── Rendering ─────────────────────────────────────────────────────────
  function renderGraph() {
    if (rendered) return;
    rendered = true;

    var model    = buildLayout();
    var techNodes = model.techNodes;
    var links     = model.links;
    var CANVAS_H  = model.CANVAS_H;
    var CANVAS_W  = model.CANVAS_W;

    // Container width - reads correctly because container is visible at this point
    var wrapEl   = document.getElementById('ttp-graph-svg-wrap');
    var displayW = (wrapEl && wrapEl.offsetWidth > 0) ? wrapEl.offsetWidth : 800;
    var displayH = Math.min(CANVAS_H, 420);

    // CSS variable reads for theme-aware colors
    var cs = getComputedStyle(document.documentElement);
    function cssVar(n) { return cs.getPropertyValue(n).trim() || null; }
    var accent    = cssVar('--accent')    || '#f0883e';
    var borderClr = cssVar('--border')    || '#30363d';
    var textMuted = cssVar('--text-muted') || '#8b949e';
    var bgCard    = cssVar('--bg-card')   || '#161b22';

    // SVG
    svgEl = d3.select('#ttp-graph-svg')
      .append('svg')
      .attr('width', displayW)
      .attr('height', displayH)
      .attr('role', 'img')
      .attr('aria-label', 'TTP relationship graph - see Grid view for accessible table');

    // Zoom/pan - no drag, no tick loop
    zoomG = svgEl.append('g').attr('class', 'ttp-zoom-layer');
    var zoom = d3.zoom()
      .scaleExtent([0.2, 5])
      .on('zoom', function (event) {
        zoomG.attr('transform', event.transform);
      });
    svgEl.call(zoom);

    // Zoom button wiring
    [['ttp-gz-in', function () { svgEl.transition().duration(250).call(zoom.scaleBy, 1.4); }],
     ['ttp-gz-out', function () { svgEl.transition().duration(250).call(zoom.scaleBy, 0.7); }],
     ['ttp-gz-reset', function () { svgEl.transition().duration(250).call(zoom.transform, d3.zoomIdentity); }]
    ].forEach(function (pair) {
      var btn = document.getElementById(pair[0]);
      if (btn) btn.addEventListener('click', pair[1]);
    });

    // Fit full canvas into display on load
    var initialScale = Math.min(displayW / CANVAS_W, displayH / CANVAS_H, 1);
    svgEl.call(zoom.transform, d3.zoomIdentity.scale(initialScale));

    // Phase column labels
    zoomG.selectAll('.ttp-col-label')
      .data(phases)
      .join('text')
      .attr('class', 'ttp-col-label')
      .attr('x', function (d, i) { return PHASE_START_X + i * COL_W; })
      .attr('y', PHASE_LABEL_Y)
      .attr('fill', textMuted)
      .attr('font-size', '8px')
      .attr('font-weight', '700')
      .attr('letter-spacing', '0.04em')
      .attr('text-transform', 'uppercase')
      .style('font-family', 'inherit')
      .text(function (d) {
        return d.label.length > 13 ? d.label.slice(0, 12) + '…' : d.label;
      });

    // Edges (bezier, actor right → tech left)
    edgeSel = zoomG.append('g').attr('class', 'ttp-edges')
      .selectAll('.ttp-edge')
      .data(links)
      .join('path')
      .attr('class', 'ttp-edge')
      .attr('fill', 'none')
      .attr('stroke', function (d) { return d.color; })
      .attr('stroke-width', 1.1)
      .attr('stroke-opacity', 0.12)
      .attr('d', function (d) {
        var sx = d.source._x + ACTOR_R;
        var sy = d.source._y;
        var tx = d.target.x - TECH_R;
        var ty = d.target.y;
        var mx = (sx + tx) / 2;
        return 'M' + sx + ',' + sy +
               ' C' + mx + ',' + sy +
               ' ' + mx + ',' + ty +
               ' ' + tx + ',' + ty;
      });

    // Technique nodes
    techSel = zoomG.append('g').attr('class', 'ttp-tech-nodes')
      .selectAll('.ttp-tn')
      .data(techNodes)
      .join('g')
      .attr('class', 'ttp-tn')
      .attr('transform', function (d) {
        return 'translate(' + d.x + ',' + d.y + ')';
      });

    // Universal accent ring (drawn behind the filled circle)
    techSel.filter(function (d) { return d.isUniversal; })
      .append('circle')
      .attr('r', TECH_R + UNIV_R_EXTRA)
      .attr('fill', 'none')
      .attr('stroke', accent)
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.85);

    // Filled circle
    techSel.append('circle')
      .attr('class', 'ttp-tn-dot')
      .attr('r', TECH_R)
      .attr('fill', function (d) {
        if (d.isUniversal) return accent;
        var first = groups.find(function (g) { return d.groups.indexOf(g.id) !== -1; });
        return first ? first.color : borderClr;
      })
      .attr('fill-opacity', 0.85);

    // Technique label (name · id)
    techSel.append('text')
      .attr('x', TECH_R + 5)
      .attr('dy', '0.35em')
      .attr('fill', textMuted)
      .attr('font-size', '9px')
      .style('font-family', 'inherit')
      .style('pointer-events', 'none')
      .text(function (d) {
        var label = d.name.length > 22 ? d.name.slice(0, 21) + '…' : d.name;
        return label + ' · ' + d.techId;
      });

    // Actor nodes
    actorSel = zoomG.append('g').attr('class', 'ttp-actor-nodes')
      .selectAll('.ttp-an')
      .data(groups)
      .join('g')
      .attr('class', 'ttp-an')
      .attr('transform', function (d) {
        return 'translate(' + d._x + ',' + d._y + ')';
      })
      .style('cursor', 'pointer');

    actorSel.append('circle')
      .attr('class', 'ttp-an-ring')
      .attr('r', ACTOR_R)
      .attr('fill', function (d) { return d.color; })
      .attr('fill-opacity', 0.15)
      .attr('stroke', function (d) { return d.color; })
      .attr('stroke-width', 2);

    // Short abbreviation inside circle
    actorSel.append('text')
      .attr('dy', '0.35em')
      .attr('text-anchor', 'middle')
      .attr('fill', function (d) { return d.color; })
      .attr('font-size', '7px')
      .attr('font-weight', '700')
      .style('pointer-events', 'none')
      .text(function (d) { return d.name.split(/[\s/]/)[0].slice(0, 5); });

    // Full name to the right of circle
    actorSel.append('text')
      .attr('x', -(ACTOR_R + 5))
      .attr('dy', '0.35em')
      .attr('text-anchor', 'end')
      .attr('fill', function (d) { return d.color; })
      .attr('font-size', '9px')
      .style('pointer-events', 'none')
      .text(function (d) { return d.name; });

    // Tooltip element
    tooltip = document.querySelector('.ttp-graph-tooltip');

    // ── Technique hover ───────────────────────────────────────────────
    techSel.on('mouseover', function (event, d) {
      if (tooltip) {
        var usedByNames = d.groups.map(function (gid) {
          var g = groups.find(function (x) { return x.id === gid; });
          return g ? g.name : gid;
        }).join(', ');
        tooltip.querySelector('.tt-title').textContent = d.name;
        tooltip.querySelector('.tt-meta').textContent =
          d.techId + ' · ' + d.groups.length + ' actor' +
          (d.groups.length !== 1 ? 's' : '') + ': ' + usedByNames;
        var rect = wrapEl.getBoundingClientRect();
        tooltip.style.left = (event.clientX - rect.left + 12) + 'px';
        tooltip.style.top  = (event.clientY - rect.top  - 30) + 'px';
        tooltip.classList.add('visible');
        tooltip.removeAttribute('aria-hidden');
      }
      // Temporarily highlight just this node's edges
      edgeSel.attr('stroke-opacity', function (l) {
        return l.target.id === d.id ? 0.75 : 0.04;
      });
      techSel.select('.ttp-tn-dot').attr('fill-opacity', function (n) {
        return n.id === d.id ? 1.0 : 0.15;
      });
    }).on('mouseout', function () {
      if (tooltip) {
        tooltip.classList.remove('visible');
        tooltip.setAttribute('aria-hidden', 'true');
      }
      applyHighlight();
    });

    // ── Actor node click (toggle selection) ──────────────────────────
    actorSel.on('click', function (event, d) {
      if (selectedActors.has(d.id)) selectedActors.delete(d.id);
      else selectedActors.add(d.id);
      syncFilterButtons();
      applyHighlight();
    });

    // Filter buttons
    setupFilterButtons();

    // Resize
    var resizeTimer;
    window.addEventListener('resize', function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function () {
        if (!svgEl) return;
        var newW = wrapEl.offsetWidth || 800;
        svgEl.attr('width', newW);
      }, 250);
    });
  }

  // ── Highlight engine (union multi-select) ─────────────────────────────
  function applyHighlight() {
    if (!edgeSel) return;
    if (selectedActors.size === 0) {
      edgeSel.attr('stroke-opacity', 0.12);
      techSel.select('.ttp-tn-dot').attr('fill-opacity', 0.85);
      actorSel.select('.ttp-an-ring')
        .attr('fill-opacity', 0.15)
        .attr('stroke-opacity', 1);
    } else {
      edgeSel.attr('stroke-opacity', function (d) {
        return selectedActors.has(d.groupId) ? 0.7 : 0.04;
      });
      techSel.select('.ttp-tn-dot').attr('fill-opacity', function (d) {
        var used = d.groups.some(function (gid) { return selectedActors.has(gid); });
        return used ? 0.9 : 0.15;
      });
      actorSel.select('.ttp-an-ring')
        .attr('fill-opacity', function (d) {
          return selectedActors.has(d.id) ? 0.25 : 0.05;
        })
        .attr('stroke-opacity', function (d) {
          return selectedActors.has(d.id) ? 1 : 0.25;
        });
    }
  }

  function syncFilterButtons() {
    document.querySelectorAll('.ttp-graph-actor-btn').forEach(function (btn) {
      var active = selectedActors.has(btn.dataset.actor);
      btn.classList.toggle('state-lit', active);
      btn.setAttribute('aria-pressed', String(active));
    });
  }

  function setupFilterButtons() {
    document.querySelectorAll('.ttp-graph-actor-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var id = btn.dataset.actor;
        if (selectedActors.has(id)) selectedActors.delete(id);
        else selectedActors.add(id);
        syncFilterButtons();
        applyHighlight();
      });
    });
    var clearBtn = document.getElementById('ttp-graph-clear');
    if (clearBtn) {
      clearBtn.addEventListener('click', function () {
        selectedActors.clear();
        syncFilterButtons();
        applyHighlight();
      });
    }
  }

  // ── View toggle ───────────────────────────────────────────────────────
  var toggleBar  = document.getElementById('ttp-view-toggle');
  var graphView  = document.getElementById('ttp-graph-view');
  var gridView   = document.getElementById('ttp-grid-view');
  var graphActive = false;

  function switchView(showGraph) {
    graphActive = showGraph;
    if (graphView) graphView.hidden = !showGraph;
    if (gridView)  gridView.hidden  = showGraph;
    document.querySelectorAll('.ttp-view-btn').forEach(function (btn) {
      var isGraph = btn.dataset.view === 'graph';
      var pressed = showGraph ? isGraph : !isGraph;
      btn.classList.toggle('active', pressed);
      btn.setAttribute('aria-pressed', String(pressed));
    });
    if (showGraph) renderGraph();
  }

  // Reveal toggle bar (JS available + D3 present)
  if (toggleBar) toggleBar.hidden = false;

  // Default: desktop → Graph, mobile → Grid
  var isMobile = window.matchMedia('(max-width: 767px)').matches;
  switchView(!isMobile);

  document.querySelectorAll('.ttp-view-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      switchView(btn.dataset.view === 'graph');
    });
  });

  // Collapse to Grid on resize to mobile
  var viewResizeTimer;
  window.addEventListener('resize', function () {
    clearTimeout(viewResizeTimer);
    viewResizeTimer = setTimeout(function () {
      if (window.matchMedia('(max-width: 767px)').matches && graphActive) {
        switchView(false);
      }
    }, 250);
  });

})();
