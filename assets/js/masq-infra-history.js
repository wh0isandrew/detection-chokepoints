/**
 * masq-infra-history.js
 * Renders two SVG charts for the masq-infra historical trend section.
 * Reads from window.MASQ_HISTORY (injected by the Jekyll page via | jsonify).
 * Vanilla JS + SVG, no external dependencies.
 * Follows the same conventions as clickgrab-trends.js.
 */
(function () {
  'use strict';

  var RAW = window.MASQ_HISTORY;
  if (!RAW) return;

  var weeks = Object.keys(RAW).sort();   // YYYY-WW sorts correctly as strings
  if (weeks.length < 4) return;

  var rows = weeks.map(function (w) { return RAW[w]; });

  /* ── Palette (matches clickgrab-trends.js) ──────────────────────────── */
  var C = {
    bg:     'transparent',
    grid:   'rgba(255,255,255,0.08)',
    text:   '#8b949e',
    label:  '#c9d1d9',
    blue:   '#388bfd',
    red:    '#da3633',
    yellow: '#e3b341',
    orange: '#f0883e',
    green:  '#3fb950',
    purple: '#bc8cff',
    cyan:   '#39c5cf',
    pink:   '#f778ba',
  };

  /* ── SVG helpers ─────────────────────────────────────────────────────── */

  function svgEl(tag, attrs) {
    var el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (var k in attrs) el.setAttribute(k, attrs[k]);
    return el;
  }

  function makeSvg(w, h, label) {
    return svgEl('svg', {
      viewBox: '0 0 ' + w + ' ' + h,
      width: '100%',
      role: 'img',
      'aria-label': label || 'Chart',
    });
  }

  function text(x, y, str, opts) {
    var el = svgEl('text', Object.assign({
      x: x, y: y,
      fill: C.text,
      'font-size': '11',
      'font-family': 'ui-monospace, SFMono-Regular, monospace',
      'text-anchor': 'middle',
    }, opts || {}));
    el.textContent = str;
    return el;
  }

  /* ── Shared axes ─────────────────────────────────────────────────────── */

  function drawAxes(svg, pad, W, H, yMax, labels, ySteps) {
    for (var i = 0; i <= ySteps; i++) {
      var val = Math.round((yMax / ySteps) * i);
      var yy  = pad.top + (H - pad.top - pad.bottom) * (1 - i / ySteps);
      svg.appendChild(svgEl('line', {
        x1: pad.left, y1: yy, x2: W - pad.right, y2: yy,
        stroke: C.grid, 'stroke-width': '1',
      }));
      svg.appendChild(text(pad.left - 6, yy + 4, val, { 'text-anchor': 'end', fill: C.text }));
    }
    var chartW = W - pad.left - pad.right;
    labels.forEach(function (lbl, i) {
      var x = pad.left + (labels.length > 1 ? (i / (labels.length - 1)) * chartW : chartW / 2);
      svg.appendChild(text(x, H - pad.bottom + 16, lbl, { 'font-size': '10' }));
    });
    svg.appendChild(svgEl('line', {
      x1: pad.left, y1: pad.top, x2: pad.left, y2: H - pad.bottom,
      stroke: C.grid, 'stroke-width': '1',
    }));
  }

  /* ── Tooltip ─────────────────────────────────────────────────────────── */

  var tip = (function () {
    var el = document.createElement('div');
    el.id = 'mi-tooltip';
    el.setAttribute('aria-hidden', 'true');
    el.style.cssText = [
      'position:fixed;pointer-events:none;z-index:1000;',
      'background:#161b22;border:1px solid #30363d;border-radius:6px;',
      'padding:8px 10px;font-size:12px;font-family:ui-monospace,monospace;',
      'color:#c9d1d9;max-width:240px;line-height:1.5;',
      'opacity:0;transition:opacity .15s;',
    ].join('');
    document.body.appendChild(el);

    function show(html, cx, cy) {
      el.innerHTML = html;
      el.setAttribute('aria-hidden', 'false');
      el.style.opacity = '1';
      var mx = window.innerWidth  - 260;
      var my = window.innerHeight - 180;
      el.style.left = Math.min(cx + 12, mx) + 'px';
      el.style.top  = Math.min(cy + 12, my) + 'px';
    }
    function hide() {
      el.style.opacity = '0';
      el.setAttribute('aria-hidden', 'true');
    }
    return { show: show, hide: hide };
  }());

  function hitZone(svg, x, y, w, h, html) {
    var rect = svgEl('rect', {
      x: x - w / 2, y: y - h / 2, width: w, height: h,
      fill: 'transparent', cursor: 'crosshair',
    });
    rect.addEventListener('mouseenter', function (e) { tip.show(html, e.clientX, e.clientY); });
    rect.addEventListener('mousemove', function (e) {
      var mx = window.innerWidth  - 260;
      var my = window.innerHeight - 180;
      var t = document.getElementById('mi-tooltip');
      if (t) {
        t.style.left = Math.min(e.clientX + 12, mx) + 'px';
        t.style.top  = Math.min(e.clientY + 12, my) + 'px';
      }
    });
    rect.addEventListener('mouseleave', tip.hide);
    svg.appendChild(rect);
  }

  /* ════════════════════════════════════════════════════════════════════════
   * Chart A — Weekly domain volume (line chart)
   * ════════════════════════════════════════════════════════════════════════ */

  function renderChartVolume(containerId) {
    var el = document.getElementById(containerId);
    if (!el) return;

    var W = 760, H = 220;
    var pad = { top: 20, right: 20, bottom: 40, left: 52 };
    var svg = makeSvg(W, H, 'Weekly masq-infra domain volume');

    var vals  = rows.map(function (r) { return r.total_domains || 0; });
    var yMax  = Math.max.apply(null, vals);
    var yMaxR = Math.ceil(yMax / 50) * 50 || 50;

    drawAxes(svg, pad, W, H, yMaxR, weeks, 5);

    var n      = rows.length;
    var chartW = W - pad.left - pad.right;
    var chartH = H - pad.top - pad.bottom;

    function xOf(i) {
      return pad.left + (n > 1 ? (i / (n - 1)) * chartW : chartW / 2);
    }
    function yOf(v) { return pad.top + chartH - (v / yMaxR) * chartH; }

    // Area fill
    var areaPath = 'M ' + xOf(0) + ',' + yOf(0);
    vals.forEach(function (v, i) { areaPath += ' L ' + xOf(i) + ',' + yOf(v); });
    areaPath += ' L ' + xOf(n - 1) + ',' + yOf(0) + ' Z';
    svg.appendChild(svgEl('path', {
      d: areaPath, fill: C.blue, opacity: '0.10', stroke: 'none',
    }));

    // Line
    var linePath = vals.map(function (v, i) {
      return (i === 0 ? 'M' : 'L') + ' ' + xOf(i) + ',' + yOf(v);
    }).join(' ');
    svg.appendChild(svgEl('path', {
      d: linePath, fill: 'none', stroke: C.blue,
      'stroke-width': '2', 'stroke-linejoin': 'round', 'stroke-linecap': 'round',
    }));

    // Dots + hit zones
    vals.forEach(function (v, i) {
      svg.appendChild(svgEl('circle', {
        cx: xOf(i), cy: yOf(v), r: '3', fill: C.blue,
      }));
      var r = rows[i];
      var html = '<strong style="color:#c9d1d9">Week ' + weeks[i] + '</strong><br>'
               + '<span style="color:' + C.blue + '">&#9646; Domains: ' + v + '</span><br>'
               + '<span style="color:' + C.text + '">Campaigns: ' + (r.campaigns_identified || 0) + '</span><br>'
               + '<span style="color:' + C.text + '">LE TLS: ' + (r.lets_encrypt_pct || 0) + '%</span>';
      hitZone(svg, xOf(i), yOf(v), 24, 24, html);
    });

    // Legend (top-left)
    var lx = pad.left + 8;
    var ly = pad.top + 4;
    svg.appendChild(svgEl('line', {
      x1: lx, y1: ly + 5, x2: lx + 14, y2: ly + 5,
      stroke: C.blue, 'stroke-width': '2',
    }));
    svg.appendChild(text(lx + 18, ly + 9, 'Weekly domain count', { 'text-anchor': 'start', fill: C.label, 'font-size': '10' }));

    el.appendChild(svg);
  }

  /* ════════════════════════════════════════════════════════════════════════
   * Chart B — Lure type share over time (stacked area)
   * ════════════════════════════════════════════════════════════════════════ */

  function renderChartLures(containerId) {
    var el = document.getElementById(containerId);
    if (!el) return;

    // Gather all lure type keys across all weeks, rank by total count
    var totals = {};
    rows.forEach(function (r) {
      var lt = r.lure_types || {};
      Object.keys(lt).forEach(function (k) {
        totals[k] = (totals[k] || 0) + lt[k];
      });
    });
    var lureKeys = Object.keys(totals).sort(function (a, b) {
      return totals[b] - totals[a];
    }).slice(0, 6);

    if (!lureKeys.length) return;

    var SERIES_COLORS = [C.yellow, C.orange, C.purple, C.cyan, C.green, C.pink];

    var W = 760, H = 260;
    var pad = { top: 20, right: 20, bottom: 40, left: 52 };
    var svg = makeSvg(W, H, 'Lure type share over time');

    var n      = rows.length;
    var chartW = W - pad.left - pad.right;
    var chartH = H - pad.top - pad.bottom;

    // Compute cumulative data: cumData[weekIdx][seriesIdx] = count at TOP of band
    var cumData = rows.map(function (r) {
      var lt = r.lure_types || {};
      var cum = 0;
      return lureKeys.map(function (k) {
        cum += (lt[k] || 0);
        return cum;
      });
    });

    var stackMax = Math.max.apply(null, cumData.map(function (c) { return c[c.length - 1] || 0; }));
    var yMaxR = Math.ceil(stackMax / 50) * 50 || 50;

    drawAxes(svg, pad, W, H, yMaxR, weeks, 5);

    function xOf(i) {
      return pad.left + (n > 1 ? (i / (n - 1)) * chartW : chartW / 2);
    }
    function yOf(v) { return pad.top + chartH - (v / yMaxR) * chartH; }

    // Draw stacked bands from bottom series upward
    // Render in reverse so the bottom series sits on top visually if bands overlap
    for (var j = lureKeys.length - 1; j >= 0; j--) {
      var color = SERIES_COLORS[j];

      // Area polygon: forward at top of band, backward at bottom of band
      var fwd = cumData.map(function (c, i) {
        return xOf(i) + ',' + yOf(c[j]);
      });
      var bwd = cumData.map(function (c, i) {
        var base = j > 0 ? c[j - 1] : 0;
        return xOf(n - 1 - i) + ',' + yOf(base);
      });
      var polyPath = 'M ' + fwd.join(' L ') + ' L ' + bwd.join(' L ') + ' Z';
      svg.appendChild(svgEl('path', {
        d: polyPath, fill: color, opacity: '0.22', stroke: 'none',
      }));

      // Band top line
      var topPath = cumData.map(function (c, i) {
        return (i === 0 ? 'M' : 'L') + ' ' + xOf(i) + ',' + yOf(c[j]);
      }).join(' ');
      svg.appendChild(svgEl('path', {
        d: topPath, fill: 'none', stroke: color,
        'stroke-width': '1.5', 'stroke-linejoin': 'round', 'stroke-linecap': 'round',
        opacity: '0.8',
      }));

      // Hit zones along band top line
      var key = lureKeys[j];
      cumData.forEach(function (c, i) {
        var r = rows[i];
        var lt = r.lure_types || {};
        var count = lt[key] || 0;
        var share = stackMax > 0 ? Math.round(count / (c[lureKeys.length - 1] || 1) * 100) : 0;
        var html = '<strong style="color:#c9d1d9">Week ' + weeks[i] + '</strong><br>'
                 + '<span style="color:' + color + '">&#9646; ' + key.replace(/_/g, ' ') + ': ' + count + '</span><br>'
                 + '<span style="color:' + C.text + '">Share: ' + share + '%</span>';
        hitZone(svg, xOf(i), yOf(c[j]), 20, 20, html);
      });
    }

    // Legend (two columns if > 3 series)
    var colBreak = Math.ceil(lureKeys.length / 2);
    var lx = pad.left + 10;
    var ly = H - pad.bottom - 4 - (colBreak - 1) * 18;
    lureKeys.forEach(function (k, i) {
      var col = i < colBreak ? 0 : 1;
      var row = i < colBreak ? i : i - colBreak;
      var x   = lx + col * 175;
      var y   = ly + row * 18;
      svg.appendChild(svgEl('line', {
        x1: x, y1: y + 5, x2: x + 14, y2: y + 5,
        stroke: SERIES_COLORS[i], 'stroke-width': '2',
      }));
      svg.appendChild(text(x + 18, y + 9, k.replace(/_/g, ' '), {
        'text-anchor': 'start', fill: C.label, 'font-size': '10',
      }));
    });

    el.appendChild(svg);
  }

  /* ── Init ────────────────────────────────────────────────────────────── */

  function init() {
    renderChartVolume('mi-chart-volume');
    renderChartLures('mi-chart-lures');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

}());
