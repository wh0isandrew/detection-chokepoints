/**
 * framework-graph.js
 * D3 v7 force-directed graph visualization for the framework page.
 * Reads window.__GRAPH_DATA (set by Liquid in framework/index.html) and renders
 * an interactive graph of tactics, chokepoints, and MITRE techniques.
 */
(function () {
  'use strict';

  // Guard: bail out if data or container is missing
  if (!window.__GRAPH_DATA) return;
  var container = document.getElementById('graph-svg');
  if (!container) return;

  var graphData = window.__GRAPH_DATA;

  // Deduplicate links to prevent duplicate force edges from Liquid output
  var seenLinks = new Set();
  graphData.links = graphData.links.filter(function (l) {
    var sid = (typeof l.source === 'object') ? l.source.id : l.source;
    var tid = (typeof l.target === 'object') ? l.target.id : l.target;
    var key = sid + '|' + tid;
    if (seenLinks.has(key)) return false;
    seenLinks.add(key);
    return true;
  });

  // Read CSS custom properties at runtime so colors adapt to theme changes
  var cs = getComputedStyle(document.documentElement);
  function cssVar(name) { return cs.getPropertyValue(name).trim(); }

  var colorMap = {
    tactic:     cssVar('--medium'),
    chokepoint: cssVar('--critical'),
    technique:  cssVar('--accent')
  };
  var borderColor  = cssVar('--border');
  var textMuted    = cssVar('--text-muted');
  var textDim      = cssVar('--text-dim');
  var bgCard       = cssVar('--bg-card');

  var radiusMap = { tactic: 22, chokepoint: 16, technique: 10 };

  function radius(d) { return radiusMap[d.type] || 10; }

  // SVG setup
  var width  = container.clientWidth || 800;
  var height = 520;

  var svg = d3.select('#graph-svg')
    .append('svg')
    .attr('width', width)
    .attr('height', height)
    .attr('viewBox', [0, 0, width, height]);

  // Zoom behavior
  var zoomGroup = svg.append('g').attr('class', 'zoom-layer');
  var zoom = d3.zoom()
    .scaleExtent([0.3, 4])
    .on('zoom', function (event) {
      zoomGroup.attr('transform', event.transform);
    });
  svg.call(zoom);

  // Zoom controls
  var zoomInBtn   = document.getElementById('graph-zoom-in');
  var zoomOutBtn  = document.getElementById('graph-zoom-out');
  var zoomResetBtn = document.getElementById('graph-zoom-reset');

  if (zoomInBtn) {
    zoomInBtn.addEventListener('click', function () {
      svg.transition().duration(300).call(zoom.scaleBy, 1.4);
    });
  }
  if (zoomOutBtn) {
    zoomOutBtn.addEventListener('click', function () {
      svg.transition().duration(300).call(zoom.scaleBy, 0.7);
    });
  }
  if (zoomResetBtn) {
    zoomResetBtn.addEventListener('click', function () {
      svg.transition().duration(300).call(zoom.transform, d3.zoomIdentity);
    });
  }

  // Arrow marker definition
  svg.append('defs').append('marker')
    .attr('id', 'arrow')
    .attr('viewBox', '0 -3 6 6')
    .attr('refX', 18)
    .attr('refY', 0)
    .attr('markerWidth', 6)
    .attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M0,-3L6,0L0,3')
    .attr('fill', borderColor);

  // Force simulation
  var simulation = d3.forceSimulation(graphData.nodes)
    .force('link', d3.forceLink(graphData.links)
      .id(function (d) { return d.id; })
      .distance(function (d) {
        if (d.source.type === 'tactic' || d.target.type === 'tactic') return 140;
        return 80;
      })
    )
    .force('charge', d3.forceManyBody()
      .strength(function (d) {
        if (d.type === 'tactic') return -400;
        if (d.type === 'chokepoint') return -250;
        return -120;
      })
    )
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(function (d) { return radius(d) + 8; }));

  // Links layer (drawn first so nodes render on top)
  var link = zoomGroup.append('g')
    .selectAll('line')
    .data(graphData.links)
    .join('line')
    .attr('stroke', borderColor)
    .attr('stroke-width', 1.2)
    .attr('stroke-opacity', 0.5);

  // Nodes layer
  var node = zoomGroup.append('g')
    .selectAll('g')
    .data(graphData.nodes)
    .join('g')
    .call(d3.drag()
      .on('start', function (event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on('drag', function (event, d) {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on('end', function (event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      })
    );

  // Node circles
  node.append('circle')
    .attr('r', function (d) { return radius(d); })
    .attr('fill', function (d) { return colorMap[d.type] || colorMap.technique; })
    .attr('fill-opacity', function (d) { return d.type === 'tactic' ? 0.25 : 0.85; })
    .attr('stroke', function (d) { return colorMap[d.type] || colorMap.technique; })
    .attr('stroke-width', function (d) { return d.type === 'tactic' ? 2 : 1.5; })
    .style('cursor', function (d) { return d.type === 'chokepoint' ? 'pointer' : 'default'; });

  // Node labels
  node.append('text')
    .text(function (d) {
      if (d.type === 'tactic') return d.name;
      if (d.type === 'technique') return d.id || d.name;
      // chokepoint: truncate to 20 chars
      return (d.name && d.name.length > 20) ? d.name.substring(0, 20) + '...' : d.name;
    })
    .attr('dy', function (d) { return d.type === 'tactic' ? radiusMap.tactic + 14 : radius(d) + 12; })
    .attr('text-anchor', 'middle')
    .attr('fill', textMuted)
    .attr('font-size', function (d) { return d.type === 'tactic' ? '11px' : '9px'; })
    .attr('font-weight', function (d) { return d.type === 'tactic' ? '600' : '400'; })
    .style('pointer-events', 'none');

  // Variation count badge on chokepoints that have vars
  var cpWithVars = node.filter(function (d) { return d.type === 'chokepoint' && d.vars; });

  cpWithVars.append('circle')
    .attr('cx', 12).attr('cy', -12).attr('r', 8)
    .attr('fill', bgCard)
    .attr('stroke', textDim)
    .attr('stroke-width', 1);

  cpWithVars.append('text')
    .text(function (d) { return d.vars; })
    .attr('x', 12).attr('y', -8)
    .attr('text-anchor', 'middle')
    .attr('fill', textMuted)
    .attr('font-size', '8px')
    .attr('font-weight', '600')
    .style('pointer-events', 'none');

  // Tooltip element (created by framework/index.html)
  var tooltip = document.getElementById('graph-tooltip');

  // Hover: tooltip + connection highlighting
  node.on('mouseover', function (event, d) {
    if (tooltip) {
      var ttTitle = tooltip.querySelector('.tt-title');
      var ttMeta  = tooltip.querySelector('.tt-meta');

      if (ttTitle) ttTitle.textContent = d.name;
      if (ttMeta) {
        if (d.type === 'chokepoint') {
          ttMeta.textContent = (d.vars || 0) + ' variations \u00B7 ' + (d.maturity || '') + ' maturity';
        } else if (d.type === 'technique') {
          ttMeta.textContent = (d.id || '') + ' \u00B7 ' + d.name;
        } else {
          ttMeta.textContent = 'Tactic group';
        }
      }

      tooltip.style.left = (event.offsetX + 15) + 'px';
      tooltip.style.top  = (event.offsetY - 10) + 'px';
      tooltip.classList.add('visible');
    }

    // Build set of directly connected node IDs
    var connected = new Set();
    connected.add(d.id);
    graphData.links.forEach(function (l) {
      var sid = (typeof l.source === 'object') ? l.source.id : l.source;
      var tid = (typeof l.target === 'object') ? l.target.id : l.target;
      if (sid === d.id) connected.add(tid);
      if (tid === d.id) connected.add(sid);
    });

    // Dim unconnected nodes, brighten connected ones
    node.select('circle').attr('fill-opacity', function (n) {
      return connected.has(n.id) ? 0.95 : 0.15;
    });
    link.attr('stroke-opacity', function (l) {
      var sid = (typeof l.source === 'object') ? l.source.id : l.source;
      var tid = (typeof l.target === 'object') ? l.target.id : l.target;
      return (sid === d.id || tid === d.id) ? 0.8 : 0.07;
    });
  })
  .on('mouseout', function () {
    if (tooltip) tooltip.classList.remove('visible');
    // Reset all opacities to defaults
    node.select('circle').attr('fill-opacity', function (d) {
      return d.type === 'tactic' ? 0.25 : 0.85;
    });
    link.attr('stroke-opacity', 0.5);
  });

  // Click: navigate to chokepoint detail page
  node.on('click', function (event, d) {
    if (d.type === 'chokepoint' && d.url) {
      window.location.href = d.url;
    }
  });

  // Tick: update positions
  simulation.on('tick', function () {
    link
      .attr('x1', function (d) { return d.source.x; })
      .attr('y1', function (d) { return d.source.y; })
      .attr('x2', function (d) { return d.target.x; })
      .attr('y2', function (d) { return d.target.y; });
    node.attr('transform', function (d) {
      return 'translate(' + d.x + ',' + d.y + ')';
    });
  });

  // Tactic filter buttons
  document.querySelectorAll('.graph-btn[data-filter]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.graph-btn[data-filter]').forEach(function (b) {
        b.classList.remove('active');
      });
      btn.classList.add('active');
      var filter = btn.dataset.filter;

      if (filter === 'all') {
        node.attr('display', 'block');
        link.attr('display', 'block');
        node.select('circle').attr('fill-opacity', function (d) {
          return d.type === 'tactic' ? 0.25 : 0.85;
        });
      } else {
        // Build set of visible node IDs: nodes in the tactic group, then expand to neighbors
        var visible = new Set();
        graphData.nodes.forEach(function (n) {
          if (n.group === filter) visible.add(n.id);
        });
        // Expand: add all nodes connected to any node already in the visible set
        graphData.links.forEach(function (l) {
          var sid = (typeof l.source === 'object') ? l.source.id : l.source;
          var tid = (typeof l.target === 'object') ? l.target.id : l.target;
          if (visible.has(sid)) visible.add(tid);
          if (visible.has(tid)) visible.add(sid);
        });

        node.attr('display', function (d) { return visible.has(d.id) ? 'block' : 'none'; });
        link.attr('display', function (l) {
          var sid = (typeof l.source === 'object') ? l.source.id : l.source;
          var tid = (typeof l.target === 'object') ? l.target.id : l.target;
          return (visible.has(sid) && visible.has(tid)) ? 'block' : 'none';
        });
      }

      simulation.alpha(0.5).restart();
    });
  });

  // Responsive resize with debounce
  var resizeTimer;
  window.addEventListener('resize', function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      width = container.clientWidth || 800;
      svg.attr('width', width)
        .attr('viewBox', [0, 0, width, height]);
      simulation.force('center', d3.forceCenter(width / 2, height / 2));
      simulation.alpha(0.3).restart();
    }, 250);
  });

})();
