// P2P Swarm Monitor - 100% Offline Client-Side Polling (Phase 7)
// Strictly textContent for all network-derived content (XSS-safe)

const SENDER_PALETTE = [
  { color: '#38bdf8', letter: 'A', name: 'Sky Blue' },
  { color: '#fb923c', letter: 'B', name: 'Orange' },
  { color: '#34d399', letter: 'C', name: 'Emerald' },
  { color: '#a78bfa', letter: 'D', name: 'Purple' },
  { color: '#f43f5e', letter: 'E', name: 'Rose' },
  { color: '#a3e635', letter: 'F', name: 'Lime' }
];

const COLOR_MISSING = '#1e293b';
const COLOR_PARTIAL = '#b45309';
const COLOR_MIXED = '#9333ea';

// Formatting utilities
function formatBytes(bytes) {
  if (bytes === 0 || !bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatSpeed(bps) {
  if (!bps || bps <= 0) return '0 B/s';
  return formatBytes(bps) + '/s';
}

function formatEta(seconds) {
  if (!seconds || seconds <= 0 || !isFinite(seconds)) return '--:--';
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;
}

function formatTime(unixSec) {
  if (!unixSec) return '';
  const d = new Date(unixSec * 1000);
  return d.toTimeString().split(' ')[0];
}

// DOM helper creating element with textContent
function createEl(tag, className, textContent) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (textContent !== undefined && textContent !== null) {
    el.textContent = textContent;
  }
  return el;
}

function getSenderColor(colorIndex) {
  if (colorIndex !== undefined && colorIndex >= 0 && colorIndex < SENDER_PALETTE.length) {
    return SENDER_PALETTE[colorIndex].color;
  }
  return SENDER_PALETTE[0].color;
}

function getSenderLetter(colorIndex) {
  if (colorIndex !== undefined && colorIndex >= 0 && colorIndex < SENDER_PALETTE.length) {
    return SENDER_PALETTE[colorIndex].letter;
  }
  return '?';
}

// Banner controls
const bannerEl = document.getElementById('tracker-banner');
const bannerMsgEl = document.getElementById('tracker-banner-msg');

function showBanner(message) {
  if (bannerEl) {
    bannerMsgEl.textContent = message || '⚠️ Tracker Unreachable — Attempting to reconnect...';
    bannerEl.classList.remove('hidden');
  }
}

function hideBanner() {
  if (bannerEl) {
    bannerEl.classList.add('hidden');
  }
}

// Main Render Function
function renderDashboard(state) {
  if (!state) return;

  // 1. Header & Overall Progress
  const swarm = state.swarm || {};
  const transfer = state.transfer || {};
  const tracker = state.tracker || {};

  const swarmNameEl = document.getElementById('swarm-name');
  if (swarmNameEl) swarmNameEl.textContent = swarm.name || 'P2P Swarm';

  const swarmIdEl = document.getElementById('swarm-id');
  if (swarmIdEl) swarmIdEl.textContent = swarm.swarm_id_short || '--------';

  const badgeTlsEl = document.getElementById('badge-tls');
  if (badgeTlsEl) badgeTlsEl.textContent = tracker.tls ? 'TLS ON' : 'TLS OFF';

  const badgeAuthEl = document.getElementById('badge-auth');
  if (badgeAuthEl) badgeAuthEl.textContent = tracker.auth ? 'AUTH ON' : 'AUTH OFF';

  const badgeStateEl = document.getElementById('badge-state');
  if (badgeStateEl) {
    const st = (transfer.state || 'idle').toUpperCase();
    badgeStateEl.textContent = st;
    badgeStateEl.className = 'badge badge-state ' + (transfer.state || 'idle');
  }

  const piecesDone = transfer.pieces_done || 0;
  const totalPieces = swarm.total_pieces || 0;
  const pct = totalPieces > 0 ? (piecesDone / totalPieces) * 100 : 0;

  const barFillEl = document.getElementById('progress-bar-fill');
  if (barFillEl) barFillEl.style.width = pct.toFixed(1) + '%';

  const progressTextEl = document.getElementById('progress-text');
  if (progressTextEl) {
    progressTextEl.textContent = piecesDone + ' / ' + totalPieces + ' pieces (' + pct.toFixed(1) + '%)';
  }

  const progressBytesEl = document.getElementById('progress-bytes');
  if (progressBytesEl) {
    progressBytesEl.textContent = formatBytes(transfer.bytes_done) + ' / ' + formatBytes(swarm.total_bytes);
  }

  const metricSpeedEl = document.getElementById('metric-speed');
  if (metricSpeedEl) metricSpeedEl.textContent = formatSpeed(transfer.speed_bps);

  const metricEtaEl = document.getElementById('metric-eta');
  if (metricEtaEl) metricEtaEl.textContent = formatEta(transfer.eta_s);

  const metricFilesEl = document.getElementById('metric-files');
  if (metricFilesEl) {
    metricFilesEl.textContent = (transfer.files_done || 0) + ' / ' + (swarm.files_total || 0);
  }

  const metricBadEl = document.getElementById('metric-bad');
  if (metricBadEl) metricBadEl.textContent = String(transfer.bad_pieces || 0);

  // Map device_id to sender record for quick lookup
  const senders = state.senders || [];
  const senderMap = new Map();
  senders.forEach(s => senderMap.set(s.device_id, s));

  // 2. Devices Section
  renderDevices(state.devices || [], swarm.swarm_id_short, senderMap);

  // 3. Live Transfer Map (Inline SVG)
  renderTransferMap(senders, tracker, transfer);

  // 4. Piece Map
  renderPieceMap(state.piece_map, senders);

  // 5. Files
  renderFiles(state.files || [], senders, senderMap);

  // 6. Sender Stats Table
  renderSenderTable(senders);

  // 7. Event Log
  renderEvents(state.events || []);
}

// 2. Render Devices
function renderDevices(devices, currentSwarmShort, senderMap) {
  const container = document.getElementById('devices-container');
  const countEl = document.getElementById('devices-count');
  if (!container) return;

  if (countEl) countEl.textContent = devices.length + ' registered';

  const cards = devices.map(dev => {
    const card = createEl('div', 'device-card');

    const header = createEl('div', 'device-card-header');
    const nameRow = createEl('div', 'device-name-row');

    const dot = createEl('div', 'status-dot ' + (dev.status === 'online' ? 'online' : 'offline'));
    const name = createEl('div', 'device-name', dev.name || dev.device_id || 'Device');
    nameRow.appendChild(dot);
    nameRow.appendChild(name);

    const roleBadge = createEl('span', 'badge', (dev.role || 'peer').toUpperCase());
    header.appendChild(nameRow);
    header.appendChild(roleBadge);
    card.appendChild(header);

    const meta = createEl('div', 'device-meta', (dev.ip || '0.0.0.0') + ':' + (dev.tcp_port || dev.port || 0));
    card.appendChild(meta);

    const badgesRow = createEl('div', 'device-badges');
    const trustClass = dev.trust === 'verified' ? 'verified' : (dev.trust === 'banned' ? 'banned' : 'discovered');
    badgesRow.appendChild(createEl('span', 'badge-trust ' + trustClass, dev.trust || 'discovered'));

    if (dev.swarm_short && currentSwarmShort && dev.swarm_short === currentSwarmShort && dev.trust !== 'verified') {
      badgesRow.appendChild(createEl('span', 'badge-peer', 'Possible Peer'));
    }

    if (dev.last_seen_age !== undefined) {
      badgesRow.appendChild(createEl('span', 'device-meta', 'seen ' + dev.last_seen_age + 's ago'));
    }

    card.appendChild(badgesRow);
    return card;
  });

  container.replaceChildren(...cards);
}

// 3. Render Live Transfer Map (Inline SVG)
function renderTransferMap(senders, tracker, transfer) {
  const svg = document.getElementById('transfer-svg');
  if (!svg) return;

  // Clear existing SVG children safely
  svg.replaceChildren();

  const width = 800;
  const height = 240;
  const rxX = 680;
  const rxY = height / 2;

  // Create defs for arrowheads and gradients
  const svgNS = 'http://www.w3.org/2000/svg';
  const defs = document.createElementNS(svgNS, 'defs');
  svg.appendChild(defs);

  if (senders.length === 0) {
    const text = document.createElementNS(svgNS, 'text');
    text.setAttribute('x', width / 2);
    text.setAttribute('y', height / 2);
    text.setAttribute('fill', '#64748b');
    text.setAttribute('text-anchor', 'middle');
    text.textContent = 'Waiting for active seeders...';
    svg.appendChild(text);
    return;
  }

  const numSenders = senders.length;
  const spacing = height / (numSenders + 1);

  senders.forEach((s, idx) => {
    const txX = 120;
    const txY = spacing * (idx + 1);
    const color = getSenderColor(s.color_index);
    const letter = getSenderLetter(s.color_index);
    const isOffline = s.status === 'offline' || s.status === 'banned';

    // Flow line connecting Sender to Receiver
    const totalBytesDone = transfer.bytes_done || 1;
    const share = s.bytes > 0 ? (s.bytes / totalBytesDone) : (1 / Math.max(1, numSenders));
    const strokeWidth = Math.max(2, Math.min(12, Math.round(share * 14)));

    const path = document.createElementNS(svgNS, 'path');
    const d = `M ${txX} ${txY} C ${txX + 220} ${txY}, ${rxX - 220} ${rxY}, ${rxX} ${rxY}`;
    path.setAttribute('d', d);
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', isOffline ? '#475569' : color);
    path.setAttribute('stroke-width', strokeWidth);
    path.setAttribute('stroke-opacity', isOffline ? '0.25' : '0.7');

    if (!isOffline && transfer.state === 'downloading') {
      path.setAttribute('stroke-dasharray', '8 4');
    }
    svg.appendChild(path);

    // Label with pieces and speed along the midpoint
    const midX = (txX + rxX) / 2 - 40;
    const midY = (txY + rxY) / 2 + (idx % 2 === 0 ? -10 : 16);
    const label = document.createElementNS(svgNS, 'text');
    label.setAttribute('x', midX);
    label.setAttribute('y', midY);
    label.setAttribute('fill', isOffline ? '#64748b' : color);
    label.setAttribute('font-size', '11');
    label.setAttribute('font-family', 'sans-serif');
    label.setAttribute('font-weight', '600');
    label.textContent = `${letter}: ${s.pieces || 0} pcs • ${formatSpeed(s.speed_bps)}`;
    svg.appendChild(label);

    // Sender Node Circle
    const nodeCircle = document.createElementNS(svgNS, 'circle');
    nodeCircle.setAttribute('cx', txX);
    nodeCircle.setAttribute('cy', txY);
    nodeCircle.setAttribute('r', '18');
    nodeCircle.setAttribute('fill', '#0f172a');
    nodeCircle.setAttribute('stroke', isOffline ? '#475569' : color);
    nodeCircle.setAttribute('stroke-width', '3');
    svg.appendChild(nodeCircle);

    // Sender Letter
    const nodeText = document.createElementNS(svgNS, 'text');
    nodeText.setAttribute('x', txX);
    nodeText.setAttribute('y', txY + 4);
    nodeText.setAttribute('text-anchor', 'middle');
    nodeText.setAttribute('fill', isOffline ? '#64748b' : color);
    nodeText.setAttribute('font-size', '13');
    nodeText.setAttribute('font-weight', 'bold');
    nodeText.setAttribute('font-family', 'sans-serif');
    nodeText.textContent = letter;
    svg.appendChild(nodeText);

    // Sender Name Label
    const nameLabel = document.createElementNS(svgNS, 'text');
    nameLabel.setAttribute('x', txX - 25);
    nameLabel.setAttribute('y', txY + 4);
    nameLabel.setAttribute('text-anchor', 'end');
    nameLabel.setAttribute('fill', '#f8fafc');
    nameLabel.setAttribute('font-size', '12');
    nameLabel.setAttribute('font-family', 'sans-serif');
    nameLabel.textContent = s.name || s.device_id || 'Sender';
    svg.appendChild(nameLabel);
  });

  // Central Receiver Node
  const rxCircle = document.createElementNS(svgNS, 'circle');
  rxCircle.setAttribute('cx', rxX);
  rxCircle.setAttribute('cy', rxY);
  rxCircle.setAttribute('r', '24');
  rxCircle.setAttribute('fill', '#0f172a');
  rxCircle.setAttribute('stroke', '#38bdf8');
  rxCircle.setAttribute('stroke-width', '3');
  svg.appendChild(rxCircle);

  const rxText = document.createElementNS(svgNS, 'text');
  rxText.setAttribute('x', rxX);
  rxText.setAttribute('y', rxY + 5);
  rxText.setAttribute('text-anchor', 'middle');
  rxText.setAttribute('fill', '#38bdf8');
  rxText.setAttribute('font-size', '12');
  rxText.setAttribute('font-weight', 'bold');
  rxText.setAttribute('font-family', 'sans-serif');
  rxText.textContent = 'RX';
  svg.appendChild(rxText);

  const rxName = document.createElementNS(svgNS, 'text');
  rxName.setAttribute('x', rxX + 32);
  rxName.setAttribute('y', rxY + 5);
  rxName.setAttribute('fill', '#f8fafc');
  rxName.setAttribute('font-size', '12');
  rxName.setAttribute('font-weight', '600');
  rxName.setAttribute('font-family', 'sans-serif');
  rxName.textContent = tracker.name || 'Receiver';
  svg.appendChild(rxName);
}

// 4. Render Piece Map
function renderPieceMap(pieceMap, senders) {
  const legendEl = document.getElementById('piece-legend');
  const gridEl = document.getElementById('piece-grid');
  const metaEl = document.getElementById('piece-map-meta');
  if (!gridEl) return;

  const data = pieceMap ? (pieceMap.data || []) : [];
  const cells = pieceMap ? (pieceMap.cells || data.length) : 0;
  const perCell = pieceMap ? (pieceMap.per_cell || 1) : 1;

  if (metaEl) {
    metaEl.textContent = `${cells} cells • ${perCell} pieces/cell`;
  }

  // Populate Legend
  if (legendEl) {
    const legendItems = [];

    // Missing swatch
    const missingItem = createEl('div', 'legend-item');
    const missingSwatch = createEl('div', 'legend-swatch', '-');
    missingSwatch.style.background = COLOR_MISSING;
    missingSwatch.style.color = '#94a3b8';
    missingItem.appendChild(missingSwatch);
    missingItem.appendChild(createEl('span', null, 'Missing'));
    legendItems.push(missingItem);

    // Partial swatch
    const partialItem = createEl('div', 'legend-item');
    const partialSwatch = createEl('div', 'legend-swatch', '~');
    partialSwatch.style.background = COLOR_PARTIAL;
    partialSwatch.style.color = '#ffffff';
    partialItem.appendChild(partialSwatch);
    partialItem.appendChild(createEl('span', null, 'Partly missing'));
    legendItems.push(partialItem);

    // Mixed swatch
    const mixedItem = createEl('div', 'legend-item');
    const mixedSwatch = createEl('div', 'legend-swatch', 'M');
    mixedSwatch.style.background = COLOR_MIXED;
    mixedSwatch.style.color = '#ffffff';
    mixedItem.appendChild(mixedSwatch);
    mixedItem.appendChild(createEl('span', null, 'Mixed sources'));
    legendItems.push(mixedItem);

    // Each active sender
    senders.forEach(s => {
      const item = createEl('div', 'legend-item');
      const letter = getSenderLetter(s.color_index);
      const color = getSenderColor(s.color_index);

      const swatch = createEl('div', 'legend-swatch', letter);
      swatch.style.background = color;
      item.appendChild(swatch);
      item.appendChild(createEl('span', null, s.name || s.device_id || `Sender ${letter}`));
      legendItems.push(item);
    });

    legendEl.replaceChildren(...legendItems);
  }

  // Populate Grid Cells
  const cellNodes = data.map((val, idx) => {
    const cell = createEl('div', 'piece-cell');
    let titleText = `Cell ${idx} (Piece ${idx * perCell} - ${(idx + 1) * perCell - 1}): `;

    if (val === -1) {
      cell.style.backgroundColor = COLOR_MISSING;
      titleText += 'Missing';
    } else if (val === -3) {
      cell.style.backgroundColor = COLOR_PARTIAL;
      titleText += 'Partly missing';
    } else if (val === -2) {
      cell.style.backgroundColor = COLOR_MIXED;
      titleText += 'Mixed senders';
    } else {
      const color = getSenderColor(val);
      const letter = getSenderLetter(val);
      cell.style.backgroundColor = color;
      titleText += `Supplied by Sender ${letter}`;
    }

    cell.title = titleText;
    return cell;
  });

  gridEl.replaceChildren(...cellNodes);
}

// 5. Render Files Section
function renderFiles(files, senders, senderMap) {
  const container = document.getElementById('files-list');
  const summaryEl = document.getElementById('files-summary');
  if (!container) return;

  const completedCount = files.filter(f => f.complete).length;
  if (summaryEl) {
    summaryEl.textContent = `${completedCount} of ${files.length} complete`;
  }

  const items = files.map(f => {
    const item = createEl('div', 'file-item');

    const header = createEl('div', 'file-header');
    const pathSpan = createEl('span', 'file-path', f.path || 'Unnamed file');
    const sizeSpan = createEl('span', 'file-size', `${formatBytes(f.length)} • ${f.pieces_done || 0}/${f.pieces_total || 0} pcs`);
    header.appendChild(pathSpan);
    header.appendChild(sizeSpan);
    item.appendChild(header);

    // Stacked Segmented Progress Bar
    const barBg = createEl('div', 'stacked-bar-bg');
    const bySender = f.by_sender || {};
    const totalFileBytes = f.length || 1;

    let contributedBytes = 0;
    Object.entries(bySender).forEach(([devId, bytes]) => {
      contributedBytes += bytes;
      const s = senderMap.get(devId);
      const colorIndex = s ? s.color_index : 0;
      const color = getSenderColor(colorIndex);
      const letter = getSenderLetter(colorIndex);

      const segment = createEl('div', 'stacked-segment');
      const widthPct = Math.min(100, (bytes / totalFileBytes) * 100);
      segment.style.width = widthPct + '%';
      segment.style.backgroundColor = color;
      segment.title = `Sender ${letter} (${s ? s.name : devId}): ${formatBytes(bytes)} (${widthPct.toFixed(1)}%)`;
      barBg.appendChild(segment);
    });

    item.appendChild(barBg);
    return item;
  });

  container.replaceChildren(...items);
}

// 6. Render Sender Stats Table
function renderSenderTable(senders) {
  const tbody = document.getElementById('sender-table-body');
  const summaryEl = document.getElementById('senders-summary');
  if (!tbody) return;

  if (summaryEl) {
    summaryEl.textContent = `${senders.length} active seeders`;
  }

  const rows = senders.map(s => {
    const tr = createEl('tr');
    const letter = getSenderLetter(s.color_index);
    const color = getSenderColor(s.color_index);

    // Sender Name with Letter Badge
    const tdName = createEl('td');
    const swatch = createEl('span', 'legend-swatch', letter);
    swatch.style.background = color;
    swatch.style.display = 'inline-flex';
    swatch.style.marginRight = '0.5rem';
    tdName.appendChild(swatch);
    tdName.appendChild(createEl('span', null, s.name || s.device_id || 'Sender'));
    tr.appendChild(tdName);

    // IP : Port
    tr.appendChild(createEl('td', null, s.device_id || '-'));

    // Pieces
    tr.appendChild(createEl('td', null, String(s.pieces || 0)));

    // Bytes
    tr.appendChild(createEl('td', null, formatBytes(s.bytes || 0)));

    // Speed
    tr.appendChild(createEl('td', null, formatSpeed(s.speed_bps || 0)));

    // Failures
    const tdFail = createEl('td', null, String(s.failures || 0));
    if (s.failures > 0) tdFail.style.color = '#f87171';
    tr.appendChild(tdFail);

    // Status
    const tdStatus = createEl('td');
    const badge = createEl('span', 'badge ' + (s.status === 'active' ? 'badge-tls' : 'badge-state failed'), s.status || 'active');
    tdStatus.appendChild(badge);
    tr.appendChild(tdStatus);

    return tr;
  });

  tbody.replaceChildren(...rows);
}

// 7. Render Event Log
function renderEvents(events) {
  const container = document.getElementById('events-list');
  if (!container) return;

  const eventNodes = events.map(ev => {
    const levelClass = (ev.level || 'info').toLowerCase();
    const row = createEl('div', 'event-row ' + levelClass);

    const timeSpan = createEl('span', 'event-time', formatTime(ev.t));
    const typeSpan = createEl('span', 'event-type', `[${ev.type || 'EVENT'}]`);
    const msgSpan = createEl('span', 'event-msg', ev.msg || '');

    row.appendChild(timeSpan);
    row.appendChild(typeSpan);
    row.appendChild(msgSpan);
    return row;
  });

  container.replaceChildren(...eventNodes);
}

// Polling loop
function fetchState() {
  fetch('/api/state')
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      hideBanner();
      renderDashboard(data);
    })
    .catch(err => {
      showBanner(`⚠️ Tracker unreachable (${err.message}) — Attempting to reconnect...`);
    });
}

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  fetchState();
  setInterval(fetchState, 1000);
});
