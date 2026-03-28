/**
 * ttp-filter.js
 * Interactive actor filter for the vertical TTP overlap diagram.
 * Reads window.TTP_FILTER_GROUPS (injected by _includes/ttp-vertical-diagram.html).
 */
(function () {
  'use strict';

  var selected = new Set();
  var actorColors = {};

  function init() {
    // Build actor → color map from injected data
    var groups = window.TTP_FILTER_GROUPS;
    if (!groups) return;
    groups.forEach(function (g) { actorColors[g.id] = g.color; });

    // Wire filter buttons
    document.querySelectorAll('.ttp-filter-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var actor = btn.dataset.actor;
        if (selected.has(actor)) {
          selected.delete(actor);
        } else {
          selected.add(actor);
        }
        renderFilter();
      });
    });

    // Wire clear button
    var clearBtn = document.getElementById('ttp-clear');
    if (clearBtn) {
      clearBtn.addEventListener('click', function () {
        selected.clear();
        renderFilter();
      });
    }
  }

  function renderFilter() {
    var cells        = document.querySelectorAll('.ttp-cell');
    var connectors   = document.querySelectorAll('.stage-connector');
    var filterBtns   = document.querySelectorAll('.ttp-filter-btn');
    var clearBtn     = document.getElementById('ttp-clear');

    // ── Reset all states ────────────────────────────────────────────────
    cells.forEach(function (c) {
      c.classList.remove('state-dim', 'state-lit');
      c.style.removeProperty('--lit-color');
    });
    connectors.forEach(function (c) { c.classList.remove('connector-dim'); });
    filterBtns.forEach(function (b) {
      b.classList.remove('faded', 'active');
      b.setAttribute('aria-pressed', 'false');
    });
    document.querySelectorAll('.ttp-cell-dots .dot').forEach(function (d) {
      d.classList.remove('dot-active');
      d.style.removeProperty('--dot-ring');
    });

    // ── Show / hide clear button ────────────────────────────────────────
    if (clearBtn) {
      if (selected.size > 0) {
        clearBtn.classList.add('visible');
      } else {
        clearBtn.classList.remove('visible');
      }
    }

    // ── Neutral state — nothing selected ───────────────────────────────
    if (selected.size === 0) return;

    // ── Update legend button states ─────────────────────────────────────
    filterBtns.forEach(function (b) {
      if (selected.has(b.dataset.actor)) {
        b.classList.add('active');
        b.setAttribute('aria-pressed', 'true');
      } else {
        b.classList.add('faded');
      }
    });

    // ── Process each TTP cell ───────────────────────────────────────────
    cells.forEach(function (cell) {
      var actors  = (cell.dataset.actors || '').split(',').filter(Boolean);
      var matched = actors.filter(function (a) { return selected.has(a); });

      if (matched.length === 0) {
        cell.classList.add('state-dim');
      } else {
        cell.classList.add('state-lit');
        cell.style.setProperty('--lit-color', actorColors[matched[0]] || '#f0883e');

        // Ring the matching actor dots inside this cell
        cell.querySelectorAll('.ttp-cell-dots .dot[data-actor]').forEach(function (dot) {
          if (selected.has(dot.dataset.actor)) {
            dot.classList.add('dot-active');
            dot.style.setProperty('--dot-ring', actorColors[dot.dataset.actor] || '');
          }
        });
      }
    });

    // ── Dim connectors between stages where neither side has lit cells ──
    var stageRows = document.querySelectorAll('.ttp-stage-row');
    connectors.forEach(function (connector, i) {
      var prevRow = stageRows[i];
      var nextRow = stageRows[i + 1];
      if (!prevRow || !nextRow) return;
      var prevLit = prevRow.querySelectorAll('.ttp-cell.state-lit').length;
      var nextLit = nextRow.querySelectorAll('.ttp-cell.state-lit').length;
      if (prevLit === 0 && nextLit === 0) {
        connector.classList.add('connector-dim');
      }
    });
  }

  // ── Boot ────────────────────────────────────────────────────────────────
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
