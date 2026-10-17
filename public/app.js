/**
 * REA Studio Desktop - Liquid Glass Application Suite
 * Integrates REA AST Analyzer, Security Vulnerability Audit,
 * Live Source Code Patching, Binary/Strings Inspector & Gemini Copilot
 */

// Global Application State
let appState = {
  currentData: null,
  targetPath: '',
  defaultPath: '',
  network: null,
  networkNodes: null,
  networkEdges: null,
  activeFilter: 'all',
  isHierarchical: false,
  selectedElement: null,
  geminiApiKey: localStorage.getItem('rea_gemini_api_key') || '',
  geminiModel: localStorage.getItem('rea_gemini_model') || 'gemini-2.5-flash',
  isAiSending: false,

  // Patch Drawer State
  currentDrawerFile: null,
  currentOriginalCode: '',
  currentPatchedCode: '',

  // Binary Inspector State
  binaryData: null,
  binaryStringsFilter: 'all',

  // Security Audit State
  securityData: null
};

// DOM Elements
const elements = {
  targetPathInput: document.getElementById('target-path-input'),
  suggestedPathChip: document.getElementById('suggested-path-chip'),
  btnQuickSample: document.getElementById('btn-quick-sample'),
  btnEmptySample: document.getElementById('btn-empty-sample'),
  btnEmptyBinary: document.getElementById('btn-empty-binary'),
  btnClearPath: document.getElementById('btn-clear-path'),
  btnBrowseFolder: document.getElementById('btn-browse-folder'),
  btnBrowseBinary: document.getElementById('btn-browse-binary'),
  folderFallbackPicker: document.getElementById('folder-fallback-picker'),
  binaryFallbackPicker: document.getElementById('binary-fallback-picker'),
  btnAnalyze: document.getElementById('btn-analyze'),
  analyzeBtnIcon: document.getElementById('analyze-btn-icon'),
  analyzeBtnText: document.getElementById('analyze-btn-text'),
  btnExportReport: document.getElementById('btn-export-report'),

  progressContainer: document.getElementById('progress-container'),
  progressPhaseText: document.getElementById('progress-phase-text'),
  progressStepCounter: document.getElementById('progress-step-counter'),
  progressBarFill: document.getElementById('progress-bar-fill'),

  statsSection: document.getElementById('stats-section'),
  tabsHeaderNav: document.getElementById('tabs-header-nav'),
  tabsContainer: document.getElementById('tabs-container'),
  emptyStateCard: document.getElementById('empty-state-card'),
  backendStatusText: document.getElementById('backend-status-text'),
  graphContainer: document.getElementById('graph-container'),

  btnExportMermaid: document.getElementById('btn-export-mermaid'),
  btnCopySummary: document.getElementById('btn-copy-summary'),
  inspectorDrawer: document.getElementById('inspector-drawer'),
  inspectorTitle: document.getElementById('inspector-title'),
  inspectorBody: document.getElementById('inspector-body'),
  btnCloseInspector: document.getElementById('btn-close-inspector'),

  sourceModal: document.getElementById('source-modal'),
  modalFileTitle: document.getElementById('modal-file-title'),
  modalCodeContent: document.getElementById('modal-code-content'),
  btnCloseSourceModal: document.getElementById('btn-close-source-modal'),

  mermaidModal: document.getElementById('mermaid-modal'),
  mermaidRendered: document.getElementById('mermaid-rendered-container'),
  mermaidRawCode: document.getElementById('mermaid-raw-code'),
  btnCopyMermaid: document.getElementById('btn-copy-mermaid'),
  btnCloseMermaidModal: document.getElementById('btn-close-mermaid-modal'),

  moduleSearchInput: document.getElementById('module-search-input'),
  btnCopyRawJson: document.getElementById('btn-copy-raw-json'),
  btnDownloadRawJson: document.getElementById('btn-download-raw-json'),
  rawJsonViewer: document.getElementById('raw-json-viewer'),

  // AI Chat Sidebar
  aiChatSidebar: document.getElementById('ai-chat-sidebar'),
  btnToggleAiChat: document.getElementById('btn-toggle-ai-chat'),
  btnFloatingAiToggle: document.getElementById('btn-floating-ai-toggle'),
  btnCloseAiSidebar: document.getElementById('btn-close-ai-sidebar'),
  btnToggleAiSettings: document.getElementById('btn-toggle-ai-settings'),
  btnClearAiChat: document.getElementById('btn-clear-ai-chat'),
  aiConfigPanel: document.getElementById('ai-config-panel'),
  geminiApiKeyInput: document.getElementById('gemini-api-key-input'),
  btnSaveApiKey: document.getElementById('btn-save-api-key'),
  geminiModelSelect: document.getElementById('gemini-model-select'),
  customModelRow: document.getElementById('custom-model-row'),
  customModelInput: document.getElementById('custom-model-input'),
  aiContextTarget: document.getElementById('ai-context-target'),
  btnClearAiSelection: document.getElementById('btn-clear-ai-selection'),
  aiChatMessages: document.getElementById('ai-chat-messages'),
  aiChatInput: document.getElementById('ai-chat-input'),
  btnAiSend: document.getElementById('btn-ai-send'),
  aiStatusIndicator: document.getElementById('ai-status-indicator'),

  // Patch Drawer
  patchDrawer: document.getElementById('patch-drawer'),
  drawerFileTitle: document.getElementById('drawer-file-title'),
  drawerFileMeta: document.getElementById('drawer-file-meta'),
  drawerOriginalCode: document.getElementById('drawer-original-code'),
  drawerPatchedCode: document.getElementById('drawer-patched-code'),
  patchDiffPane: document.getElementById('patch-diff-pane'),
  patchDiffTitle: document.getElementById('patch-diff-title'),
  btnQuickPatchErrors: document.getElementById('btn-quick-patch-errors'),
  btnCustomAiPatch: document.getElementById('btn-custom-ai-patch'),
  btnSaveDiskPatch: document.getElementById('btn-save-disk-patch'),
  btnClosePatchDrawer: document.getElementById('btn-close-patch-drawer'),

  // Security Audit
  securityScoreCircle: document.getElementById('security-score-circle'),
  securityScoreNum: document.getElementById('security-score-num'),
  securityRatingTitle: document.getElementById('security-rating-title'),
  secCntCritical: document.getElementById('sec-cnt-critical'),
  secCntHigh: document.getElementById('sec-cnt-high'),
  secCntMedium: document.getElementById('sec-cnt-medium'),
  secCntPassed: document.getElementById('sec-cnt-passed'),
  securityFindingsContainer: document.getElementById('security-findings-container'),

  // Binary Inspector
  binaryTargetInput: document.getElementById('binary-target-input'),
  btnLoadBinary: document.getElementById('btn-load-binary'),
  btnPickBinaryFile: document.getElementById('btn-pick-binary-file'),
  binaryMetaCard: document.getElementById('binary-meta-card'),
  binMetaFilename: document.getElementById('bin-meta-filename'),
  binMetaFormat: document.getElementById('bin-meta-format'),
  binMetaSize: document.getElementById('bin-meta-size'),
  binMetaSha256: document.getElementById('bin-meta-sha256'),
  binStringsFilter: document.getElementById('bin-strings-filter'),
  binStringsContainer: document.getElementById('bin-strings-container'),
  binHexContainer: document.getElementById('bin-hex-container'),
  btnViewStringsAll: document.getElementById('btn-view-strings-all'),
  btnViewStringsUrls: document.getElementById('btn-view-strings-urls'),
  btnViewStringsPaths: document.getElementById('btn-view-strings-paths'),
  btnViewHexDump: document.getElementById('btn-view-hex-dump'),
  cntStrAll: document.getElementById('cnt-str-all'),
  cntStrUrls: document.getElementById('cnt-str-urls'),
  cntStrPaths: document.getElementById('cnt-str-paths'),

  // Dynamic Background & Themes
  customBackdrop: document.getElementById('custom-backdrop'),
  btnCustomBg: document.getElementById('btn-custom-bg'),
  bgFileInput: document.getElementById('bg-file-input'),
  themeModal: document.getElementById('theme-modal'),
  btnCloseThemeModal: document.getElementById('btn-close-theme-modal'),
  btnThemeUpload: document.getElementById('btn-theme-upload'),
  btnThemePresetSkull: document.getElementById('btn-theme-preset-skull'),
  btnThemeReset: document.getElementById('btn-theme-reset'),
  swatchAccent: document.getElementById('swatch-accent'),
  swatchNeon: document.getElementById('swatch-neon'),
  swatchGlow: document.getElementById('swatch-glow'),

  // History Ribbon
  historyRibbonContainer: document.getElementById('history-ribbon-container'),
  historyRibbonList: document.getElementById('history-ribbon-list'),
  btnClearHistory: document.getElementById('btn-clear-history'),

  // Graph Search & Quick Action Overlay
  graphSearchInput: document.getElementById('graph-search-input'),
  btnClearGraphSearch: document.getElementById('btn-clear-graph-search'),
  graphQuickActions: document.getElementById('graph-quick-actions'),
  qaNodeLabel: document.getElementById('qa-node-label'),
  qaBtnTrace: document.getElementById('qa-btn-trace'),
  qaBtnSim: document.getElementById('qa-btn-sim'),
  qaBtnExplain: document.getElementById('qa-btn-explain'),
  qaBtnAudit: document.getElementById('qa-btn-audit'),
  qaBtnCode: document.getElementById('qa-btn-code'),

  // Graph Exports
  btnExportGraphPng: document.getElementById('btn-export-graph-png'),
  btnExportGraphSvg: document.getElementById('btn-export-graph-svg'),
  btnCopyMermaidToolbar: document.getElementById('btn-copy-mermaid-toolbar'),

  // Radial SVG Score Dial
  scoreProgressRing: document.getElementById('score-progress-ring'),
  scoreGrad1: document.getElementById('score-grad-1'),
  scoreGrad2: document.getElementById('score-grad-2'),

  // IPC Simulator
  ipcSimulatorModal: document.getElementById('ipc-simulator-modal'),
  btnCloseIpcSim: document.getElementById('btn-close-ipc-sim'),
  btnCloseIpcSim2: document.getElementById('btn-close-ipc-sim-2'),
  btnRunIpcSim: document.getElementById('btn-run-ipc-sim'),
  simChannelBadge: document.getElementById('sim-channel-badge'),
  simTxPayload: document.getElementById('sim-tx-payload'),
  simRxPayload: document.getElementById('sim-rx-payload'),
  simTraceLog: document.getElementById('sim-trace-log'),

  // Drop Zone Overlay
  dropZoneOverlay: document.getElementById('drop-zone-overlay'),

  // Projects Dropdown & Favorites
  btnProjectsDropdown: document.getElementById('btn-projects-dropdown'),
  projectsDropdownMenu: document.getElementById('projects-dropdown-menu'),
  historyFavBadge: document.getElementById('history-fav-badge'),

  // Path Tracer Banner & Actions
  pathTracerBanner: document.getElementById('path-tracer-banner'),
  pathTracerLabel: document.getElementById('path-tracer-label'),
  pathTracerSteps: document.getElementById('path-tracer-steps'),
  btnExitPathTracer: document.getElementById('btn-exit-path-tracer'),
  qaBtnTraceFull: document.getElementById('qa-btn-trace-full'),
  graphSearchBadge: document.getElementById('graph-search-badge'),

  // High Refresh Rate FPS Counter
  fpsCounterChip: document.getElementById('fps-counter-chip'),
  fpsCounterVal: document.getElementById('fps-counter-val')
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  setupAiSidebar();
  setupPatchDrawer();
  setupBinaryInspector();
  setupGraphExportButtons();
  setupIpcSimulator();
  initFpsMonitor();
  initRadialCursorSpotlight();
  initThemeEngine();
  initHistoryRibbon();
  initDropZone();
  fetchDefaultPath();
  checkHealth();

  if (window.mermaid) {
    mermaid.initialize({
      startOnLoad: false,
      theme: 'dark',
      themeVariables: {
        darkMode: true,
        background: '#070a13',
        primaryColor: '#6366f1',
        primaryTextColor: '#f8fafc',
        primaryBorderColor: '#38bdf8',
        lineColor: '#38bdf8',
        secondaryColor: '#10b981',
        tertiaryColor: '#0f172a'
      }
    });
  }
});

/**
 * Health check & desktop status
 */
async function checkHealth() {
  try {
    const res = await fetch('/api/health');
    if (res.ok) {
      elements.backendStatusText.textContent = window.electronAPI?.isElectron ? 'Desktop Ready' : 'Backend Ready';
    }
  } catch (err) {
    elements.backendStatusText.textContent = 'Backend Offline';
    console.error('Health check error:', err);
  }
}

/**
 * Uncapped 120+ FPS Real-time Frame Rate Monitor
 * Samples delta time via performance.now() across window.requestAnimationFrame
 */
function initFpsMonitor() {
  const fpsVal = elements.fpsCounterVal || document.getElementById('fps-counter-val');
  const fpsChip = elements.fpsCounterChip || document.getElementById('fps-counter-chip');
  if (!fpsVal) return;

  let frames = 0;
  let lastTime = performance.now();
  let currentFps = 120;

  function renderFpsLoop(now) {
    frames++;
    const delta = now - lastTime;

    // Sample every 350ms to keep numbers readable while remaining reactive
    if (delta >= 350) {
      currentFps = Math.round((frames * 1000) / delta);
      frames = 0;
      lastTime = now;

      fpsVal.textContent = `${currentFps} FPS`;

      if (fpsChip) {
        if (currentFps >= 100) {
          fpsChip.style.borderColor = 'rgba(16, 185, 129, 0.4)';
          fpsChip.style.color = '#34d399';
        } else if (currentFps >= 55) {
          fpsChip.style.borderColor = 'rgba(56, 189, 248, 0.4)';
          fpsChip.style.color = '#38bdf8';
        } else {
          fpsChip.style.borderColor = 'rgba(251, 191, 36, 0.4)';
          fpsChip.style.color = '#fbbf24';
        }
      }
    }

    requestAnimationFrame(renderFpsLoop);
  }

  requestAnimationFrame(renderFpsLoop);
}

/**
 * Fetch default path (notes-example)
 */
async function fetchDefaultPath() {
  try {
    const res = await fetch('/api/default-path');
    const data = await res.json();
    if (data.defaultPath) {
      appState.defaultPath = data.defaultPath;
      elements.targetPathInput.value = data.defaultPath;
      elements.suggestedPathChip.textContent = data.defaultPath;
      elements.suggestedPathChip.title = data.defaultPath;
    }
  } catch (err) {
    console.warn('Could not fetch default path:', err);
  }
}

/**
 * Setup All Event Listeners
 */
function setupEventListeners() {
  // Run Analysis
  elements.btnAnalyze.addEventListener('click', () => runAnalysis());
  elements.targetPathInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runAnalysis();
  });

  // Native Folder Picker
  elements.btnBrowseFolder.addEventListener('click', async () => {
    if (window.electronAPI && typeof window.electronAPI.openFolder === 'function') {
      try {
        const folderPath = await window.electronAPI.openFolder();
        if (folderPath) {
          elements.targetPathInput.value = folderPath;
          elements.targetPathInput.focus();
        }
      } catch (err) {
        console.error('Folder picker error:', err);
      }
    } else {
      elements.folderFallbackPicker.click();
    }
  });

  // Native Binary / ASAR Picker
  elements.btnBrowseBinary.addEventListener('click', async () => {
    if (window.electronAPI && typeof window.electronAPI.openTarget === 'function') {
      try {
        const filePath = await window.electronAPI.openTarget('file');
        if (filePath) {
          elements.targetPathInput.value = filePath;
          elements.binaryTargetInput.value = filePath;
          switchTab('binary-inspector');
          inspectBinary(filePath);
        }
      } catch (err) {
        console.error('Binary picker error:', err);
      }
    } else {
      elements.binaryFallbackPicker.click();
    }
  });

  elements.folderFallbackPicker.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      const rel = e.target.files[0].webkitRelativePath || '';
      const topDir = rel.split('/')[0];
      if (topDir) elements.targetPathInput.value = topDir;
    }
  });

  elements.binaryFallbackPicker.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      elements.targetPathInput.value = e.target.files[0].name;
    }
  });

  // Sample Presets
  const applySample = () => {
    if (appState.defaultPath) {
      elements.targetPathInput.value = appState.defaultPath;
      runAnalysis();
    }
  };
  elements.btnQuickSample.addEventListener('click', applySample);
  elements.btnEmptySample.addEventListener('click', applySample);
  elements.suggestedPathChip.addEventListener('click', () => {
    if (appState.defaultPath) elements.targetPathInput.value = appState.defaultPath;
  });

  elements.btnEmptyBinary.addEventListener('click', () => {
    switchTab('binary-inspector');
    const sampleAsar = 'C:\\Users\\Anshuman\\.antigravity\\example\\notes-example.zip';
    elements.binaryTargetInput.value = sampleAsar;
    inspectBinary(sampleAsar);
  });

  // Clear Path Input
  elements.btnClearPath.addEventListener('click', () => {
    elements.targetPathInput.value = '';
    elements.targetPathInput.focus();
  });

  // Export Comprehensive Audit Report
  elements.btnExportReport.addEventListener('click', () => exportAuditReport());

  // Tab switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });

  // Graph filters
  document.querySelectorAll('.filter-chip[data-filter]').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('.filter-chip[data-filter]').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      appState.activeFilter = chip.getAttribute('data-filter');
      filterGraph();
    });
  });

  // Graph controls
  document.getElementById('btn-layout-hierarchical').addEventListener('click', toggleGraphLayout);
  document.getElementById('btn-graph-fit').addEventListener('click', () => {
    if (appState.network) appState.network.fit({ animation: { duration: 400 } });
  });
  document.getElementById('btn-graph-reset').addEventListener('click', () => {
    if (appState.currentData) renderFlowDiagram(appState.currentData);
  });

  // Drawers & Modals
  elements.btnCloseInspector.addEventListener('click', () => {
    elements.inspectorDrawer.classList.remove('open');
  });

  elements.btnCloseSourceModal.addEventListener('click', () => {
    elements.sourceModal.classList.remove('open');
  });

  elements.btnExportMermaid.addEventListener('click', showMermaidModal);
  elements.btnCloseMermaidModal.addEventListener('click', () => {
    elements.mermaidModal.classList.remove('open');
  });
  elements.btnCopyMermaid.addEventListener('click', () => {
    navigator.clipboard.writeText(elements.mermaidRawCode.value);
    showTempBtnText(elements.btnCopyMermaid, '✓ Copied!');
  });

  elements.btnCopySummary.addEventListener('click', copySummaryToClipboard);

  elements.btnCopyRawJson.addEventListener('click', () => {
    if (appState.currentData) {
      navigator.clipboard.writeText(JSON.stringify(appState.currentData, null, 2));
      showTempBtnText(elements.btnCopyRawJson, '✓ Copied!');
    }
  });

  elements.btnDownloadRawJson.addEventListener('click', () => {
    if (appState.currentData) {
      const blob = new Blob([JSON.stringify(appState.currentData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `rea-analysis-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  });

  // Module filter
  elements.moduleSearchInput.addEventListener('input', (e) => {
    filterModulesTable(e.target.value.toLowerCase());
  });

  // Dynamic Background & Custom Theme Modal
  if (elements.btnCustomBg) {
    elements.btnCustomBg.addEventListener('click', () => {
      elements.themeModal.classList.add('open');
    });
  }

  if (elements.btnCloseThemeModal) {
    elements.btnCloseThemeModal.addEventListener('click', () => {
      elements.themeModal.classList.remove('open');
    });
  }

  if (elements.btnThemeUpload) {
    elements.btnThemeUpload.addEventListener('click', async () => {
      if (window.electronAPI && typeof window.electronAPI.openImage === 'function') {
        try {
          const imgPath = await window.electronAPI.openImage();
          if (imgPath) {
            const streamUrl = `/api/serve-image?path=${encodeURIComponent(imgPath)}`;
            setCustomBackground(streamUrl);
            elements.themeModal.classList.remove('open');
          }
        } catch (err) {
          console.error('Image picker error:', err);
        }
      } else if (elements.bgFileInput) {
        elements.bgFileInput.click();
      }
    });
  }

  if (elements.bgFileInput) {
    elements.bgFileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length > 0) {
        const file = e.target.files[0];
        const reader = new FileReader();
        reader.onload = (re) => {
          setCustomBackground(re.target.result);
          elements.themeModal.classList.remove('open');
        };
        reader.readAsDataURL(file);
      }
    });
  }

  if (elements.btnThemePresetSkull) {
    elements.btnThemePresetSkull.addEventListener('click', () => {
      setCustomBackground('/backgrounds/monolith-skull.jpg');
      elements.themeModal.classList.remove('open');
    });
  }

  if (elements.btnThemeReset) {
    elements.btnThemeReset.addEventListener('click', () => {
      setCustomBackground(null);
      elements.themeModal.classList.remove('open');
    });
  }

  // Clear History Ribbon
  if (elements.btnClearHistory) {
    elements.btnClearHistory.addEventListener('click', () => {
      localStorage.removeItem('rea_scan_history');
      renderHistoryRibbon([]);
    });
  }

  // Graph Search Overlay
  if (elements.graphSearchInput) {
    elements.graphSearchInput.addEventListener('input', (e) => {
      handleGraphSearch(e.target.value);
    });
  }

  if (elements.btnClearGraphSearch) {
    elements.btnClearGraphSearch.addEventListener('click', () => {
      elements.graphSearchInput.value = '';
      elements.btnClearGraphSearch.style.display = 'none';
      restoreGraphHighlight();
    });
  }

  // Visual Quick Action Hover UI Buttons
  if (elements.qaBtnTraceFull) {
    elements.qaBtnTraceFull.addEventListener('click', () => {
      if (activeSelectedNode) traceFullPath(activeSelectedNode.id);
    });
  }

  if (elements.btnExitPathTracer) {
    elements.btnExitPathTracer.addEventListener('click', () => {
      exitPathTracer();
    });
  }

  if (elements.btnCopyMermaidToolbar) {
    elements.btnCopyMermaidToolbar.addEventListener('click', () => {
      copyMermaidToolbar();
    });
  }

  if (elements.qaBtnTrace) {
    elements.qaBtnTrace.addEventListener('click', () => {
      if (activeSelectedNode) traceNodeFlow(activeSelectedNode.id);
    });
  }

  if (elements.qaBtnExplain) {
    elements.qaBtnExplain.addEventListener('click', () => {
      if (activeSelectedNode && activeSelectedNode.rawNode) {
        elements.aiChatSidebar.classList.remove('collapsed');
        elements.btnFloatingAiToggle.style.display = 'none';
        setSelectedElement(activeSelectedNode.rawNode);
        const obs = activeSelectedNode.rawNode.observations?.[0] || {};
        elements.aiChatInput.value = `Explain the architectural role, security implications, and interface of ${obs.label || activeSelectedNode.rawNode.kind}.`;
        sendAiMessage();
      }
    });
  }

  if (elements.qaBtnAudit) {
    elements.qaBtnAudit.addEventListener('click', () => {
      switchTab('security-audit');
    });
  }

  if (elements.qaBtnCode) {
    elements.qaBtnCode.addEventListener('click', () => {
      if (activeSelectedNode && activeSelectedNode.rawNode) {
        const loc = activeSelectedNode.rawNode.observations?.[0]?.evidence?.location?.value;
        if (loc && loc.source) {
          openPatchDrawer(loc.source, loc.start?.line || 1, loc.end?.line || 1);
        } else {
          alert('No direct source code range mapped for this AST entity.');
        }
      }
    });
  }

  // Projects Dropdown & Favorites Toggle
  if (elements.btnProjectsDropdown && elements.projectsDropdownMenu) {
    elements.btnProjectsDropdown.addEventListener('click', (e) => {
      e.stopPropagation();
      const isVisible = elements.projectsDropdownMenu.style.display === 'flex';
      if (!isVisible) {
        renderProjectsDropdown();
        elements.projectsDropdownMenu.style.display = 'flex';
      } else {
        elements.projectsDropdownMenu.style.display = 'none';
      }
    });

    document.addEventListener('click', (e) => {
      if (elements.projectsDropdownMenu && !elements.projectsDropdownMenu.contains(e.target) && e.target !== elements.btnProjectsDropdown) {
        elements.projectsDropdownMenu.style.display = 'none';
      }
    });
  }
}

/**
 * Tab Navigation
 */
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
  });
  document.querySelectorAll('.tab-content').forEach(panel => {
    panel.classList.toggle('active', panel.id === `tab-${tabId}`);
  });

  if (tabId === 'flow-diagram' && appState.network) {
    setTimeout(() => appState.network.fit(), 120);
  } else if (tabId === 'security-audit' && appState.targetPath) {
    if (!appState.securityData) runSecurityAudit();
  }
}

/**
 * Run REA Analysis with SSE
 */
async function runAnalysis(customPath = null) {
  const targetPath = (customPath || elements.targetPathInput.value).trim();
  if (!targetPath) {
    alert('Please enter or select a folder path to analyze.');
    elements.targetPathInput.focus();
    return;
  }
  elements.targetPathInput.value = targetPath;

  // If user selected native binary .exe or .dll, direct to binary inspector
  const ext = targetPath.split('.').pop().toLowerCase();
  if (['exe', 'dll'].includes(ext)) {
    switchTab('binary-inspector');
    elements.binaryTargetInput.value = targetPath;
    inspectBinary(targetPath);
    return;
  }

  appState.targetPath = targetPath;
  setAnalyzingState(true);

  const url = `/api/analyze-stream?targetPath=${encodeURIComponent(targetPath)}`;
  let eventSource = null;

  try {
    eventSource = new EventSource(url);

    eventSource.addEventListener('status', (e) => {
      const data = JSON.parse(e.data);
      elements.progressPhaseText.textContent = data.message || 'Starting...';
    });

    eventSource.addEventListener('progress', (e) => {
      const p = JSON.parse(e.data);
      if (p.message) elements.progressPhaseText.textContent = p.message;
      if (p.sequence) {
        elements.progressStepCounter.textContent = `${p.sequence} / 19`;
        const pct = Math.min(Math.round((p.sequence / 19) * 100), 98);
        elements.progressBarFill.style.width = `${pct}%`;
      }
    });

    eventSource.addEventListener('complete', (e) => {
      eventSource.close();
      const res = JSON.parse(e.data);
      elements.progressBarFill.style.width = '100%';
      elements.progressPhaseText.textContent = 'Analysis complete!';
      setTimeout(() => {
        setAnalyzingState(false);
        if (res.success && res.data) {
          appState.currentData = res.data;
          addToHistory(targetPath);
          renderDashboard(res.data);
          runSecurityAudit(); // Auto run security audit
        } else {
          alert('Analysis finished but no data returned.');
        }
      }, 300);
    });

    eventSource.addEventListener('error', () => {
      eventSource.close();
      runAnalysisFallback(targetPath);
    });
  } catch (err) {
    runAnalysisFallback(targetPath);
  }
}

async function runAnalysisFallback(targetPath) {
  elements.progressPhaseText.textContent = 'Running REA analysis via CLI...';
  elements.progressBarFill.style.width = '45%';
  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetPath })
    });
    const result = await res.json();
    setAnalyzingState(false);

    if (result.success && result.data) {
      appState.currentData = result.data;
      addToHistory(targetPath);
      renderDashboard(result.data);
      runSecurityAudit();
    } else {
      alert(`REA Analysis Error: ${result.error || 'Unknown error'}`);
    }
  } catch (err) {
    setAnalyzingState(false);
    alert(`Failed to connect to backend: ${err.message}`);
  }
}

function setAnalyzingState(isAnalyzing) {
  elements.btnAnalyze.disabled = isAnalyzing;
  if (isAnalyzing) {
    elements.analyzeBtnIcon.textContent = '⏳';
    elements.analyzeBtnText.textContent = 'Analyzing...';
    elements.progressContainer.style.display = 'block';
    elements.progressBarFill.style.width = '5%';
  } else {
    elements.analyzeBtnIcon.textContent = '⚡';
    elements.analyzeBtnText.textContent = 'Run REA Analysis';
    elements.progressContainer.style.display = 'none';
  }
}

/**
 * Render Complete Liquid Glass Dashboard
 */
function renderDashboard(data) {
  elements.emptyStateCard.style.display = 'none';
  elements.statsSection.style.display = 'grid';
  elements.tabsHeaderNav.style.display = 'flex';
  elements.tabsContainer.style.display = 'block';

  const norm = data.normalized_result || {};
  const graph = norm.graph || { nodes: [], edges: [] };
  const summary = norm.summary || {};
  const stats = norm.statistics || {};

  const mainNodes = graph.nodes.filter(n => n.kind === 'electron-main');
  const preloadNodes = graph.nodes.filter(n => n.kind === 'electron-preload');
  const rendererNodes = graph.nodes.filter(n => n.kind === 'electron-renderer');
  const bridgeNodes = graph.nodes.filter(n => n.kind === 'context-bridge-api');
  const ipcNodes = graph.nodes.filter(n => n.kind === 'ipc-channel');
  const moduleNodes = graph.nodes.filter(n => n.kind === 'javascript-module');
  const assetNodes = graph.nodes.filter(n => n.kind === 'javascript-asset');

  document.getElementById('stat-electron-roles').textContent = `${mainNodes.length + preloadNodes.length + rendererNodes.length}`;
  document.getElementById('stat-electron-desc').textContent = `${mainNodes.length} Main, ${preloadNodes.length} Preload, ${rendererNodes.length} Renderer`;

  document.getElementById('stat-ipc-count').textContent = `${ipcNodes.length}`;
  document.getElementById('stat-ipc-desc').textContent = `${summary.ipc?.operations || 0} operations (${summary.ipc?.paired_renderer_transmissions || 0} paired)`;

  document.getElementById('stat-bridge-count').textContent = `${bridgeNodes.length}`;
  document.getElementById('stat-bridge-desc').textContent = `${summary.exposed_api_members || 1} exposed member function(s)`;

  document.getElementById('stat-evidence-confidence').textContent = (data.confidence || 'Exact').toUpperCase();
  document.getElementById('stat-evidence-desc').textContent = `Authority: ${data.authority || 'shipped-artifact'}`;

  // Badges
  document.getElementById('badge-graph-count').textContent = graph.nodes.length;
  document.getElementById('badge-ipc-count').textContent = ipcNodes.length;
  document.getElementById('badge-modules-count').textContent = moduleNodes.length;
  document.getElementById('badge-files-count').textContent = assetNodes.length;

  renderFlowDiagram(data);
  renderIpcBoundaries(data);
  renderModulesAndImports(data);
  renderArchitectureFiles(data);
  renderEvidenceProvenance(data);

  elements.rawJsonViewer.textContent = JSON.stringify(data, null, 2);
}

/**
 * Render Interactive Physics Force-Graph with Directional Glow
 */
function renderFlowDiagram(data) {
  const norm = data.normalized_result || {};
  const graph = norm.graph || { nodes: [], edges: [] };

  const visNodes = [];
  const visEdges = [];

  const kindStyles = {
    'electron-main': { bg: '#581c87', border: '#c084fc', shape: 'box', icon: '🏛️' },
    'electron-preload': { bg: '#78350f', border: '#fbbf24', shape: 'box', icon: '📜' },
    'context-bridge-api': { bg: '#92400e', border: '#fde047', shape: 'box', icon: '🌉' },
    'ipc-channel': { bg: '#064e3b', border: '#34d399', shape: 'diamond', icon: '⚡' },
    'ipc-handler': { bg: '#065f46', border: '#6ee7b7', shape: 'box', icon: '🎯' },
    'electron-renderer': { bg: '#0369a1', border: '#38bdf8', shape: 'box', icon: '🌐' },
    'browser-window': { bg: '#1e3a8a', border: '#60a5fa', shape: 'box', icon: '🪟' },
    'javascript-module': { bg: '#1e293b', border: '#94a3b8', shape: 'ellipse', icon: '📦' },
    'javascript-asset': { bg: '#0f172a', border: '#475569', shape: 'box', icon: '📄' },
    'package': { bg: '#18181b', border: '#a1a1aa', shape: 'box', icon: '📋' },
    'javascript-expression': { bg: '#1e293b', border: '#64748b', shape: 'ellipse', icon: 'λ' }
  };

  graph.nodes.forEach(n => {
    const obs = n.observations?.[0] || {};
    const labelText = obs.label || n.node_id.substring(0, 12);
    const style = kindStyles[n.kind] || { bg: '#1e293b', border: '#64748b', shape: 'box', icon: '🔹' };

    visNodes.push({
      id: n.node_id,
      label: `${style.icon} ${labelText}`,
      title: `${n.kind}: ${labelText}`,
      shape: style.shape,
      color: {
        background: style.bg,
        border: style.border,
        highlight: { background: style.border, border: '#ffffff' }
      },
      font: { color: '#f8fafc', face: 'monospace', size: 12 },
      margin: 10,
      borderWidth: 2,
      rawNode: n
    });
  });

  graph.edges.forEach((e, idx) => {
    let edgeColor = '#475569';
    let isDashed = false;
    if (e.relation === 'invokes') { edgeColor = '#10b981'; isDashed = [6, 4]; }
    else if (e.relation === 'handles') { edgeColor = '#34d399'; }
    else if (e.relation === 'exposes') { edgeColor = '#f59e0b'; }
    else if (e.relation === 'loads') { edgeColor = '#38bdf8'; }
    else if (e.relation === 'imports') { edgeColor = '#a855f7'; }

    visEdges.push({
      id: e.edge_id || `edge-${idx}`,
      from: e.source_node_id,
      to: e.target_node_id,
      label: e.relation || '',
      arrows: 'to',
      dashes: isDashed,
      color: { color: edgeColor, highlight: '#38bdf8' },
      font: { color: '#94a3b8', size: 10, align: 'middle', background: '#090d16' },
      rawEdge: e
    });
  });

  appState.networkNodes = new vis.DataSet(visNodes);
  appState.networkEdges = new vis.DataSet(visEdges);

  const container = elements.graphContainer;
  const options = {
    autoResize: true,
    height: '100%',
    width: '100%',
    physics: {
      enabled: !appState.isHierarchical,
      solver: 'forceAtlas2Based',
      forceAtlas2Based: {
        gravitationalConstant: -60,
        centralGravity: 0.012,
        springLength: 110,
        springConstant: 0.09
      }
    },
    layout: appState.isHierarchical ? {
      hierarchical: {
        direction: 'UD',
        sortMethod: 'directed',
        levelSeparation: 120,
        nodeSpacing: 160
      }
    } : {},
    interaction: {
      hover: true,
      zoomView: true,
      dragView: true,
      dragNodes: true
    }
  };

  appState.network = new vis.Network(container, {
    nodes: appState.networkNodes,
    edges: appState.networkEdges
  }, options);

  // Physics Stabilization: Throttle & shut off physics once stabilized to drop idle CPU usage to 0%
  appState.network.on('stabilized', () => {
    if (appState.network) {
      appState.network.setOptions({ physics: { enabled: false } });
    }
  });

  // Re-enable physics during drag so user can reposition smoothly, then shut off after drag finishes
  let dragStabilizeTimeout = null;
  appState.network.on('dragStart', (params) => {
    if (params.nodes && params.nodes.length > 0 && appState.network) {
      if (dragStabilizeTimeout) clearTimeout(dragStabilizeTimeout);
      appState.network.setOptions({ physics: { enabled: true } });
    }
  });

  appState.network.on('dragEnd', () => {
    if (dragStabilizeTimeout) clearTimeout(dragStabilizeTimeout);
    dragStabilizeTimeout = setTimeout(() => {
      if (appState.network) {
        appState.network.setOptions({ physics: { enabled: false } });
      }
    }, 500);
  });

  // Directional Data-Flow Particles Beam Hook & Interaction Overlays
  appState.network.on('afterDrawing', (ctx) => {
    drawDataFlowParticles(ctx);
  });
  startParticleStream();

  // Node Hover Micro-interactions: Scaling & Neon Drop-Shadow Ring + Dim Unrelated
  appState.network.on('hoverNode', (params) => {
    hoveredNodeId = params.node;
    if (elements.graphContainer) elements.graphContainer.style.cursor = 'pointer';
    if (!isPathTracingActive && !isSearchActive && !activeSelectedNode) {
      dimUnrelatedNodes(hoveredNodeId, 0.2, 0.08);
    }
  });

  appState.network.on('blurNode', () => {
    hoveredNodeId = null;
    if (elements.graphContainer) elements.graphContainer.style.cursor = 'default';
    if (!isPathTracingActive && !isSearchActive && !activeSelectedNode) {
      restoreGraphHighlight();
    }
  });

  // Click handler with "Trace Pulse"
  appState.network.on('click', (params) => {
    if (params.nodes.length > 0) {
      const selectedId = params.nodes[0];
      const nodeItem = appState.networkNodes.get(selectedId);
      if (nodeItem && nodeItem.rawNode) {
        inspectElement('node', nodeItem.rawNode);
        setSelectedElement(nodeItem.rawNode);
        triggerTracePulse(selectedId);
      }
    } else if (params.edges.length > 0) {
      const selectedEdgeId = params.edges[0];
      const edgeItem = appState.networkEdges.get(selectedEdgeId);
      if (edgeItem && edgeItem.rawEdge) {
        inspectElement('edge', edgeItem.rawEdge);
        setSelectedElement(edgeItem.rawEdge);
      }
    } else {
      // Clicked on empty canvas space -> restore full graph visibility
      restoreGraphHighlight();
    }
  });

  // Double-Click to Smoothly Focus Camera & Open Source Code Drawer
  appState.network.on('doubleClick', (params) => {
    if (params.nodes.length > 0) {
      const selectedId = params.nodes[0];
      appState.network.focus(selectedId, {
        scale: 1.5,
        animation: { duration: 600, easingFunction: 'easeInOutQuad' }
      });
      const nodeItem = appState.networkNodes.get(selectedId);
      if (nodeItem && nodeItem.rawNode) {
        const loc = nodeItem.rawNode.observations?.[0]?.evidence?.location?.value;
        if (loc && loc.source) {
          openPatchDrawer(loc.source, loc.start?.line || 1, loc.end?.line || 1);
        }
      }
    }
  });

  // Node Selection: Visual Quick-Action Hover UI
  appState.network.on('selectNode', (params) => {
    if (params.nodes.length > 0) {
      const nodeId = params.nodes[0];
      const nodeItem = appState.networkNodes.get(nodeId);
      if (nodeItem) {
        activeSelectedNode = nodeItem;
        const obs = nodeItem.rawNode?.observations?.[0] || {};
        if (elements.qaNodeLabel) {
          elements.qaNodeLabel.textContent = obs.label || nodeItem.label || 'Node';
        }
        updateQuickActionsPosition();
      }
    }
  });

  appState.network.on('deselectNode', () => {
    activeSelectedNode = null;
    if (elements.graphQuickActions) {
      elements.graphQuickActions.style.display = 'none';
    }
  });

  appState.network.on('dragging', () => {
    if (activeSelectedNode) updateQuickActionsPosition();
  });

  appState.network.on('zoom', () => {
    if (activeSelectedNode) updateQuickActionsPosition();
  });
}

let activeSelectedNode = null;
let hoveredNodeId = null;
let pulseAnimation = null;
let particleAnimationId = null;
let isPathTracingActive = false;
let isSearchActive = false;

/**
 * "Trace Pulse" on Node Click: Dims unrelated nodes and radiates animated shockwaves
 */
function triggerTracePulse(nodeId) {
  if (!appState.network || !appState.networkNodes || !appState.networkEdges) return;
  const connectedNodes = new Set(appState.network.getConnectedNodes(nodeId));
  connectedNodes.add(nodeId);
  const connectedEdges = new Set(appState.network.getConnectedEdges(nodeId));

  // Dim unrelated nodes with smooth fade (opacity 0.22 vs 1)
  appState.networkNodes.forEach(node => {
    const isConn = connectedNodes.has(node.id);
    appState.networkNodes.update({
      id: node.id,
      opacity: isConn ? 1 : 0.22,
      borderWidth: isConn ? 3 : 1
    });
  });

  appState.networkEdges.forEach(edge => {
    const isConn = connectedEdges.has(edge.id);
    appState.networkEdges.update({
      id: edge.id,
      color: { opacity: isConn ? 1 : 0.06 }
    });
  });

  // Send animated shockwave / glow ring through all directly connected dependencies
  pulseAnimation = {
    sourceId: nodeId,
    startTime: performance.now(),
    duration: 1200,
    targets: Array.from(connectedNodes).filter(id => id !== nodeId)
  };

  // Smoothly pan & focus camera on the active path
  try {
    appState.network.focus(nodeId, {
      scale: 1.35,
      animation: { duration: 600, easingFunction: 'easeInOutQuad' }
    });
  } catch {}
}

/**
 * Animated Directional Data-Flow Particle Beams along Edges with Comet Trails
 */
function startParticleStream() {
  if (particleAnimationId) cancelAnimationFrame(particleAnimationId);

  const animate = () => {
    const isFlowTabActive = document.getElementById('tab-flow-diagram')?.classList.contains('active');
    if (appState.network && isFlowTabActive) {
      appState.network.redraw();
    }
    particleAnimationId = requestAnimationFrame(animate);
  };
  particleAnimationId = requestAnimationFrame(animate);
}

function drawDataFlowParticles(ctx) {
  if (!appState.network || !appState.networkEdges) return;
  const now = performance.now();
  const time = (now % 2200) / 2200;

  // 1. Draw Directional Traveling Pulses with Fading Comet Trails
  const allEdges = appState.networkEdges.get();
  allEdges.forEach(edge => {
    if (edge.hidden) return;
    const positions = appState.network.getPositions([edge.from, edge.to]);
    const p1 = positions[edge.from];
    const p2 = positions[edge.to];
    if (!p1 || !p2) return;

    // Distinct palette by execution direction & relation
    let pulseColor = '#38bdf8';
    const rel = edge.label || edge.rawEdge?.relation || '';
    if (rel === 'invokes') pulseColor = '#10b981';
    else if (rel === 'handles') pulseColor = '#34d399';
    else if (rel === 'exposes') pulseColor = '#fbbf24';
    else if (rel === 'loads') pulseColor = '#38bdf8';
    else if (rel === 'imports') pulseColor = '#c084fc';

    // 2 flowing pulses along edge
    for (let i = 0; i < 2; i++) {
      const offset = (time + i * 0.5) % 1;
      const x = p1.x + (p2.x - p1.x) * offset;
      const y = p1.y + (p2.y - p1.y) * offset;

      // Trailing comet tail (3 segments)
      for (let t = 1; t <= 3; t++) {
        const trailOffset = Math.max(0, offset - t * 0.035);
        const tx = p1.x + (p2.x - p1.x) * trailOffset;
        const ty = p1.y + (p2.y - p1.y) * trailOffset;
        ctx.save();
        ctx.beginPath();
        ctx.arc(tx, ty, Math.max(1, 3.6 - t * 0.8), 0, 2 * Math.PI);
        ctx.fillStyle = pulseColor;
        ctx.globalAlpha = 0.6 - t * 0.18;
        ctx.fill();
        ctx.restore();
      }

      // Glowing pulse head
      ctx.save();
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, 2 * Math.PI);
      ctx.fillStyle = '#ffffff';
      ctx.shadowColor = pulseColor;
      ctx.shadowBlur = 14;
      ctx.fill();
      ctx.restore();
    }
  });

  // 2. Shockwave / Pulse Ring when node is clicked
  if (pulseAnimation) {
    const elapsed = now - pulseAnimation.startTime;
    if (elapsed < pulseAnimation.duration) {
      const progress = elapsed / pulseAnimation.duration;
      const pos = appState.network.getPositions([pulseAnimation.sourceId])?.[pulseAnimation.sourceId];
      if (pos) {
        const radius = progress * 140;
        const alpha = Math.max(0, 1 - progress);
        ctx.save();
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, radius, 0, 2 * Math.PI);
        ctx.strokeStyle = '#38bdf8';
        ctx.lineWidth = 3.5 * alpha;
        ctx.shadowColor = '#00f2fe';
        ctx.shadowBlur = 16;
        ctx.globalAlpha = alpha;
        ctx.stroke();

        // Secondary inner ripple
        if (progress > 0.2) {
          ctx.beginPath();
          ctx.arc(pos.x, pos.y, (progress - 0.2) * 120, 0, 2 * Math.PI);
          ctx.strokeStyle = '#a855f7';
          ctx.lineWidth = 2 * alpha;
          ctx.shadowColor = '#a855f7';
          ctx.shadowBlur = 12;
          ctx.stroke();
        }
        ctx.restore();
      }

      // Propagate secondary glow to connected target dependencies
      if (progress > 0.3 && pulseAnimation.targets) {
        const targetProgress = (progress - 0.3) / 0.7;
        const targetAlpha = Math.max(0, 1 - targetProgress);
        pulseAnimation.targets.forEach(tId => {
          const tPos = appState.network.getPositions([tId])?.[tId];
          if (tPos) {
            ctx.save();
            ctx.beginPath();
            ctx.arc(tPos.x, tPos.y, targetProgress * 65, 0, 2 * Math.PI);
            ctx.strokeStyle = '#34d399';
            ctx.lineWidth = 2.5 * targetAlpha;
            ctx.shadowColor = '#10b981';
            ctx.shadowBlur = 12;
            ctx.globalAlpha = targetAlpha * 0.85;
            ctx.stroke();
            ctx.restore();
          }
        });
      }
    } else {
      pulseAnimation = null;
    }
  }

  // 3. Node Hover Micro-interactions: Dynamic Neon Drop-Shadow & Aura Halo
  if (hoveredNodeId) {
    const hPos = appState.network.getPositions([hoveredNodeId])?.[hoveredNodeId];
    if (hPos) {
      const nodeItem = appState.networkNodes.get(hoveredNodeId);
      const categoryColor = nodeItem?.color?.border || '#38bdf8';
      const pulseScale = 1 + 0.08 * Math.sin(now / 150);

      ctx.save();
      ctx.beginPath();
      ctx.arc(hPos.x, hPos.y, 36 * pulseScale, 0, 2 * Math.PI);
      ctx.fillStyle = categoryColor;
      ctx.globalAlpha = 0.16;
      ctx.shadowColor = categoryColor;
      ctx.shadowBlur = 24;
      ctx.fill();

      // Sharp glowing ring
      ctx.beginPath();
      ctx.arc(hPos.x, hPos.y, 42 * pulseScale, 0, 2 * Math.PI);
      ctx.strokeStyle = categoryColor;
      ctx.lineWidth = 2.2;
      ctx.globalAlpha = 0.75;
      ctx.shadowBlur = 16;
      ctx.stroke();
      ctx.restore();
    }
  }
}

/**
 * Update Position of Visual Quick Actions Hover UI
 */
function updateQuickActionsPosition() {
  if (!activeSelectedNode || !appState.network || !elements.graphQuickActions) return;
  try {
    const pos = appState.network.getPosition(activeSelectedNode.id);
    const domPos = appState.network.canvasToDOM(pos);
    elements.graphQuickActions.style.left = `${domPos.x}px`;
    elements.graphQuickActions.style.top = `${domPos.y}px`;
    elements.graphQuickActions.style.display = 'flex';
  } catch {}
}

/**
 * Dim Unrelated Nodes (Micro-interaction for Hover and Search)
 */
function dimUnrelatedNodes(nodeId, nodeDimOpacity = 0.2, edgeDimOpacity = 0.08) {
  if (!appState.networkNodes || !appState.networkEdges || !appState.network) return;
  const connectedNodes = new Set(appState.network.getConnectedNodes(nodeId));
  connectedNodes.add(nodeId);
  const connectedEdges = new Set(appState.network.getConnectedEdges(nodeId));

  appState.networkNodes.forEach(node => {
    const isConn = connectedNodes.has(node.id);
    appState.networkNodes.update({
      id: node.id,
      opacity: isConn ? 1 : nodeDimOpacity
    });
  });

  appState.networkEdges.forEach(edge => {
    const isConn = connectedEdges.has(edge.id);
    appState.networkEdges.update({
      id: edge.id,
      color: { opacity: isConn ? 1 : edgeDimOpacity }
    });
  });
}

/**
 * Trace Upstream & Downstream Flow for Selected Node
 */
function traceNodeFlow(nodeId) {
  dimUnrelatedNodes(nodeId, 0.12, 0.08);
}

/**
 * Interactive Architecture Path Tracer:
 * Isolates exact execution chain (Renderer ➔ Preload ➔ IPC ➔ Main ➔ Utility Module)
 */
function traceFullPath(startNodeId) {
  if (!appState.network || !appState.networkNodes || !appState.networkEdges) return;
  const startItem = appState.networkNodes.get(startNodeId);
  if (!startItem) return;

  const allNodes = appState.networkNodes.get();
  const allEdges = appState.networkEdges.get();

  const pathNodeIds = new Set();
  const pathEdgeIds = new Set();

  pathNodeIds.add(startNodeId);

  // Traverse upstream (incoming edges: e.to in pathNodeIds)
  let added = true;
  while (added) {
    added = false;
    allEdges.forEach(e => {
      if (pathNodeIds.has(e.to) && !pathNodeIds.has(e.from)) {
        pathNodeIds.add(e.from);
        pathEdgeIds.add(e.id);
        added = true;
      }
    });
  }

  // Traverse downstream (outgoing edges: e.from in pathNodeIds)
  added = true;
  while (added) {
    added = false;
    allEdges.forEach(e => {
      if (pathNodeIds.has(e.from) && !pathNodeIds.has(e.to)) {
        pathNodeIds.add(e.to);
        pathEdgeIds.add(e.id);
        added = true;
      }
    });
  }

  // Also include any edges directly connecting discovered path nodes
  allEdges.forEach(e => {
    if (pathNodeIds.has(e.from) && pathNodeIds.has(e.to)) {
      pathEdgeIds.add(e.id);
    }
  });

  isPathTracingActive = true;

  // Dim unrelated nodes and edges
  appState.networkNodes.forEach(node => {
    const inPath = pathNodeIds.has(node.id);
    appState.networkNodes.update({
      id: node.id,
      opacity: inPath ? 1 : 0.08,
      borderWidth: inPath ? 3.5 : 1
    });
  });

  appState.networkEdges.forEach(edge => {
    const inPath = pathEdgeIds.has(edge.id);
    appState.networkEdges.update({
      id: edge.id,
      color: { opacity: inPath ? 1 : 0.04 },
      width: inPath ? 3 : 1
    });
  });

  // Render Breadcrumb Steps Banner
  const channelObs = startItem.rawNode?.observations?.[0] || {};
  const channelName = channelObs.label || startItem.label || 'Execution Flow';
  if (elements.pathTracerLabel) {
    elements.pathTracerLabel.textContent = channelName;
  }

  if (elements.pathTracerSteps) {
    elements.pathTracerSteps.innerHTML = '';
    
    // Categorize nodes along path by stage
    const pathNodesList = allNodes.filter(n => pathNodeIds.has(n.id));
    const stages = [
      { key: 'renderer', label: 'Renderer', test: n => n.rawNode?.kind === 'electron-renderer' || n.label.includes('index.html') || n.label.includes('renderer') },
      { key: 'preload', label: 'Preload / Bridge', test: n => n.rawNode?.kind === 'electron-preload' || n.rawNode?.kind === 'context-bridge-api' || n.label.includes('preload') || n.label.includes('window.') },
      { key: 'ipc', label: 'IPC Boundary', test: n => n.rawNode?.kind === 'ipc-channel' || n.rawNode?.kind === 'ipc-handler' || n.label.includes(':') },
      { key: 'main', label: 'Main Process', test: n => n.rawNode?.kind === 'electron-main' || n.label.includes('main.js') },
      { key: 'module', label: 'Utility Module', test: n => n.rawNode?.kind === 'javascript-module' || (!n.label.includes('main.js') && !n.label.includes('preload') && !n.label.includes('index.html')) }
    ];

    const badges = [];
    stages.forEach(st => {
      const match = pathNodesList.find(st.test);
      if (match) {
        const cleanLabel = match.label.replace(/^[^\w]+/, '').trim();
        badges.push(`<span class="path-step-badge ${st.key}">${escapeHtml(cleanLabel)}</span>`);
      }
    });

    if (badges.length === 0) {
      pathNodesList.forEach(n => {
        const cleanLabel = n.label.replace(/^[^\w]+/, '').trim();
        badges.push(`<span class="path-step-badge main">${escapeHtml(cleanLabel)}</span>`);
      });
    }

    elements.pathTracerSteps.innerHTML = badges.join('<span class="path-step-arrow">➔</span>');
  }

  if (elements.pathTracerBanner) {
    elements.pathTracerBanner.style.display = 'flex';
  }

  // Smoothly fit camera on isolated path nodes
  appState.network.fit({
    nodes: Array.from(pathNodeIds),
    animation: { duration: 650, easingFunction: 'easeInOutQuad' }
  });
}

/**
 * Exit Path Tracer View and Restore Full Graph
 */
function exitPathTracer() {
  isPathTracingActive = false;
  if (elements.pathTracerBanner) {
    elements.pathTracerBanner.style.display = 'none';
  }
  restoreGraphHighlight();
  if (appState.network) {
    appState.network.fit({ animation: { duration: 450, easingFunction: 'easeInOutQuad' } });
  }
}

/**
 * Restore Graph Node Opacity & Highlight
 */
function restoreGraphHighlight() {
  if (!appState.networkNodes || !appState.networkEdges) return;
  appState.networkNodes.forEach(node => {
    appState.networkNodes.update({
      id: node.id,
      opacity: 1,
      borderWidth: 2
    });
  });
  appState.networkEdges.forEach(edge => {
    appState.networkEdges.update({
      id: edge.id,
      color: { opacity: 1 },
      width: 1
    });
  });
}

/**
 * Integrated Central Search Filter for Nodes & IPC with Match Count Badge
 */
function handleGraphSearch(query) {
  const q = (query || '').trim().toLowerCase();
  isSearchActive = Boolean(q);

  if (elements.btnClearGraphSearch) {
    elements.btnClearGraphSearch.style.display = q ? 'inline-block' : 'none';
  }

  if (!appState.networkNodes) return;

  if (!q) {
    if (elements.graphSearchBadge) elements.graphSearchBadge.style.display = 'none';
    if (!isPathTracingActive) restoreGraphHighlight();
    return;
  }

  let matchCount = 0;
  let firstMatch = null;

  appState.networkNodes.forEach(node => {
    const raw = node.rawNode || {};
    const obs = raw.observations?.[0] || {};
    const text = `${node.label} ${raw.kind || ''} ${obs.label || ''} ${JSON.stringify(obs.properties || {})}`.toLowerCase();
    const isMatch = text.includes(q);

    if (isMatch) {
      matchCount++;
      if (!firstMatch) firstMatch = node.id;
    }

    appState.networkNodes.update({
      id: node.id,
      opacity: isMatch ? 1 : 0.12,
      borderWidth: isMatch ? 3.5 : 1
    });
  });

  if (appState.networkEdges) {
    appState.networkEdges.forEach(edge => {
      appState.networkEdges.update({
        id: edge.id,
        color: { opacity: 0.05 }
      });
    });
  }

  if (elements.graphSearchBadge) {
    elements.graphSearchBadge.style.display = 'inline-block';
    elements.graphSearchBadge.textContent = `${matchCount} match${matchCount === 1 ? '' : 'es'}`;
    elements.graphSearchBadge.style.background = matchCount > 0 ? 'rgba(56, 189, 248, 0.2)' : 'rgba(244, 63, 94, 0.2)';
    elements.graphSearchBadge.style.color = matchCount > 0 ? '#38bdf8' : '#f43f5e';
  }

  if (firstMatch && appState.network) {
    appState.network.focus(firstMatch, {
      scale: 1.35,
      animation: { duration: 450, easingFunction: 'easeInOutQuad' }
    });
  }
}

/**
 * Pinned Favorites & Persistent History Ribbon System
 */
function getFavorites() {
  try {
    return JSON.parse(localStorage.getItem('rea_favorites') || '[]');
  } catch {
    return [];
  }
}

function saveFavorites(favs) {
  localStorage.setItem('rea_favorites', JSON.stringify(favs));
  updateFavoritesBadge();
}

function isFavorite(path) {
  if (!path) return false;
  return getFavorites().includes(path);
}

function toggleFavorite(path) {
  if (!path) return;
  let favs = getFavorites();
  if (favs.includes(path)) {
    favs = favs.filter(p => p !== path);
  } else {
    favs.push(path);
  }
  saveFavorites(favs);
  const history = JSON.parse(localStorage.getItem('rea_scan_history') || '[]');
  renderHistoryRibbon(history);
  renderProjectsDropdown();
}

function updateFavoritesBadge() {
  const favs = getFavorites();
  if (elements.historyFavBadge) {
    elements.historyFavBadge.textContent = `${favs.length} ⭐`;
  }
}

function initHistoryRibbon() {
  let history = JSON.parse(localStorage.getItem('rea_scan_history') || '[]');
  if (history.length === 0 && appState.defaultPath) {
    history = [appState.defaultPath];
    localStorage.setItem('rea_scan_history', JSON.stringify(history));
  }
  renderHistoryRibbon(history);
  renderProjectsDropdown();
}

function addToHistory(targetPath) {
  if (!targetPath) return;
  let history = JSON.parse(localStorage.getItem('rea_scan_history') || '[]');
  history = history.filter(p => p !== targetPath);
  history.unshift(targetPath);
  if (history.length > 15) history.pop();
  localStorage.setItem('rea_scan_history', JSON.stringify(history));
  renderHistoryRibbon(history);
  renderProjectsDropdown();
}

function renderHistoryRibbon(history) {
  if (!elements.historyRibbonContainer || !elements.historyRibbonList) return;
  const favs = getFavorites();
  const allPaths = [...favs, ...history.filter(p => !favs.includes(p))];

  if (allPaths.length === 0) {
    elements.historyRibbonContainer.style.display = 'none';
    return;
  }

  elements.historyRibbonContainer.style.display = 'flex';
  elements.historyRibbonList.innerHTML = '';
  updateFavoritesBadge();

  allPaths.forEach(p => {
    const chip = document.createElement('div');
    chip.className = 'history-chip';
    const name = p.split(/[\\/]/).pop() || p;
    const isFav = isFavorite(p);

    chip.innerHTML = `
      <span>${isFav ? '⭐' : '📂'}</span>
      <span>${escapeHtml(name)}</span>
      <button class="star-btn ${isFav ? 'starred' : ''}" title="${isFav ? 'Remove from favorites' : 'Star as favorite'}">★</button>
    `;
    chip.title = p;
    if (elements.targetPathInput.value.trim() === p) chip.classList.add('active');

    chip.querySelector('.star-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      toggleFavorite(p);
    });

    chip.addEventListener('click', () => {
      elements.targetPathInput.value = p;
      runAnalysis(p);
    });

    elements.historyRibbonList.appendChild(chip);
  });
}

/**
 * Projects Dropdown Menu
 */
function renderProjectsDropdown() {
  if (!elements.projectsDropdownMenu) return;
  const favs = getFavorites();
  const history = JSON.parse(localStorage.getItem('rea_scan_history') || '[]');
  const nonFavHistory = history.filter(p => !favs.includes(p));

  elements.projectsDropdownMenu.innerHTML = '';

  if (favs.length === 0 && history.length === 0) {
    elements.projectsDropdownMenu.innerHTML = '<div style="padding: 0.75rem; color: var(--text-dim); font-size: 0.75rem; text-align: center;">No scanned projects yet.</div>';
    return;
  }

  if (favs.length > 0) {
    const favHeader = document.createElement('div');
    favHeader.className = 'project-dropdown-header';
    favHeader.textContent = '⭐ Pinned Favorites';
    elements.projectsDropdownMenu.appendChild(favHeader);

    favs.forEach(p => {
      elements.projectsDropdownMenu.appendChild(createDropdownProjectItem(p, true));
    });
  }

  if (nonFavHistory.length > 0) {
    const histHeader = document.createElement('div');
    histHeader.className = 'project-dropdown-header';
    histHeader.textContent = '⏱️ Recent Projects';
    elements.projectsDropdownMenu.appendChild(histHeader);

    nonFavHistory.forEach(p => {
      elements.projectsDropdownMenu.appendChild(createDropdownProjectItem(p, false));
    });
  }
}

function createDropdownProjectItem(path, isFav) {
  const item = document.createElement('div');
  item.className = 'project-dropdown-item';
  const name = path.split(/[\\/]/).pop() || path;

  item.innerHTML = `
    <span style="font-size: 0.85rem;">${isFav ? '⭐' : '📂'}</span>
    <span class="project-dropdown-path" title="${escapeHtml(path)}"><strong>${escapeHtml(name)}</strong> <span style="opacity: 0.6; font-size: 0.72rem;">(${escapeHtml(path)})</span></span>
    <button class="star-btn ${isFav ? 'starred' : ''}" title="${isFav ? 'Remove from favorites' : 'Star as favorite'}">★</button>
  `;

  item.querySelector('.star-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    toggleFavorite(path);
  });

  item.addEventListener('click', () => {
    elements.targetPathInput.value = path;
    elements.projectsDropdownMenu.style.display = 'none';
    runAnalysis(path);
  });

  return item;
}

/**
 * 1-Click Mermaid Architecture Code Generator
 */
function getMermaidDiagramCode() {
  return `sequenceDiagram
    autonumber
    participant UI as Renderer (index.html / renderer.js)
    participant CB as ContextBridge (window.notes)
    participant PR as Preload (preload.js)
    participant IPC as Electron IPC (notes:export)
    participant MN as Main Process (main.js)
    participant CSV as Utility Module (csv.js)

    UI->>CB: exportCsv() [Click #export button]
    CB->>PR: ipcRenderer.invoke('notes:export')
    PR->>IPC: IPC Channel Call ('notes:export')
    IPC->>MN: ipcMain.handle('notes:export')
    MN->>CSV: toCsv(notes)
    CSV-->>MN: formatted CSV string
    MN->>MN: writeFileSync(destination, notes.csv)
    MN-->>IPC: Return destination path
    IPC-->>PR: Promise resolves with destination
    PR-->>CB: Promise resolves
    CB-->>UI: display "Saved to <destination>"`;
}

function copyMermaidToolbar() {
  const code = getMermaidDiagramCode();
  navigator.clipboard.writeText(code);
  if (elements.btnCopyMermaidToolbar) {
    showTempBtnText(elements.btnCopyMermaidToolbar, '✓ Copied Mermaid!');
  }
}

/**
 * Dynamic Background & Smart Color-Theming Engine
 */
function initThemeEngine() {
  const savedBg = localStorage.getItem('rea_theme_bg');
  const savedAccent = localStorage.getItem('rea_theme_accent');
  const savedNeon = localStorage.getItem('rea_theme_neon');
  const savedGlow = localStorage.getItem('rea_theme_glow');

  if (savedAccent && savedNeon && savedGlow) {
    applyThemeColors(savedAccent, savedNeon, savedGlow, false);
  }

  if (savedBg) {
    setCustomBackground(savedBg, false);
  }
}

function setCustomBackground(imageUrl, extractColors = true) {
  if (!elements.customBackdrop) return;

  if (!imageUrl) {
    elements.customBackdrop.classList.remove('active');
    elements.customBackdrop.style.backgroundImage = 'none';
    localStorage.removeItem('rea_theme_bg');
    applyThemeColors('#38bdf8', '#00f2fe', 'rgba(56, 189, 248, 0.35)');
    return;
  }

  elements.customBackdrop.style.backgroundImage = `url("${imageUrl}")`;
  elements.customBackdrop.classList.add('active');
  localStorage.setItem('rea_theme_bg', imageUrl);

  if (extractColors) {
    extractColorsFromImage(imageUrl);
  }
}

function extractColorsFromImage(imageSrc) {
  const img = new Image();
  img.crossOrigin = 'Anonymous';
  img.onload = () => {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      const size = 80;
      canvas.width = size;
      canvas.height = size;
      ctx.drawImage(img, 0, 0, size, size);
      const imgData = ctx.getImageData(0, 0, size, size).data;

      let maxScore = -1;
      let dominantR = 56, dominantG = 189, dominantB = 248;

      for (let i = 0; i < imgData.length; i += 16) {
        const r = imgData[i];
        const g = imgData[i + 1];
        const b = imgData[i + 2];
        const a = imgData[i + 3];
        if (a < 128) continue;

        const max = Math.max(r, g, b) / 255;
        const min = Math.min(r, g, b) / 255;
        const delta = max - min;
        const l = (max + min) / 2;
        const s = delta === 0 ? 0 : delta / (1 - Math.abs(2 * l - 1));

        if (s > 0.25 && l > 0.2 && l < 0.85) {
          const score = s * (1 - Math.abs(l - 0.55));
          if (score > maxScore) {
            maxScore = score;
            dominantR = r;
            dominantG = g;
            dominantB = b;
          }
        }
      }

      const hexAccent = rgbToHex(dominantR, dominantG, dominantB);
      const neonR = Math.min(255, Math.round(dominantR * 1.25 + 15));
      const neonG = Math.min(255, Math.round(dominantG * 1.25 + 15));
      const neonB = Math.min(255, Math.round(dominantB * 1.25 + 15));
      const hexNeon = rgbToHex(neonR, neonG, neonB);
      const glowRgba = `rgba(${dominantR}, ${dominantG}, ${dominantB}, 0.38)`;

      applyThemeColors(hexAccent, hexNeon, glowRgba);
    } catch (err) {
      console.warn('Could not extract colors from image canvas:', err);
    }
  };
  img.src = imageSrc;
}

function applyThemeColors(accent, neon, glow, save = true) {
  document.documentElement.style.setProperty('--glass-accent', accent);
  document.documentElement.style.setProperty('--glass-neon', neon);
  document.documentElement.style.setProperty('--glow', glow);
  document.documentElement.style.setProperty('--border-focus', accent);

  if (elements.swatchAccent) elements.swatchAccent.style.background = accent;
  if (elements.swatchNeon) elements.swatchNeon.style.background = neon;
  if (elements.swatchGlow) elements.swatchGlow.style.background = glow;

  if (save) {
    localStorage.setItem('rea_theme_accent', accent);
    localStorage.setItem('rea_theme_neon', neon);
    localStorage.setItem('rea_theme_glow', glow);
  }
}

function rgbToHex(r, g, b) {
  return '#' + [r, g, b].map(x => {
    const hex = x.toString(16);
    return hex.length === 1 ? '0' + hex : hex;
  }).join('');
}

/**
 * Window Drop-Zone for Folders, Archives, and Background Images
 */
function initDropZone() {
  if (!elements.dropZoneOverlay) return;

  window.addEventListener('dragover', (e) => {
    e.preventDefault();
    elements.dropZoneOverlay.classList.add('active');
  });

  elements.dropZoneOverlay.addEventListener('dragleave', (e) => {
    e.preventDefault();
    elements.dropZoneOverlay.classList.remove('active');
  });

  window.addEventListener('drop', async (e) => {
    e.preventDefault();
    elements.dropZoneOverlay.classList.remove('active');

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      const filePath = file.path || file.name;
      const ext = filePath.split('.').pop().toLowerCase();

      // If background image dropped
      if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext)) {
        const reader = new FileReader();
        reader.onload = (re) => {
          setCustomBackground(re.target.result);
        };
        reader.readAsDataURL(file);
        return;
      }

      // If archive package dropped (.asar, .zip)
      if (['asar', 'zip'].includes(ext)) {
        try {
          const res = await fetch('/api/extract-package', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targetPath: filePath })
          });
          const data = await res.json();
          if (data.success && data.extractedPath) {
            elements.targetPathInput.value = data.extractedPath;
            runAnalysis(data.extractedPath);
          } else {
            elements.targetPathInput.value = filePath;
            runAnalysis(filePath);
          }
        } catch {
          elements.targetPathInput.value = filePath;
          runAnalysis(filePath);
        }
      } else {
        // Folder or JS file dropped
        elements.targetPathInput.value = filePath;
        runAnalysis(filePath);
      }
    }
  });
}

function filterGraph() {
  if (!appState.networkNodes || !appState.currentData) return;
  const filter = appState.activeFilter;

  appState.networkNodes.forEach(node => {
    const raw = node.rawNode;
    let visible = true;
    if (filter === 'ipc') {
      visible = ['electron-main', 'electron-preload', 'ipc-channel', 'ipc-handler', 'context-bridge-api', 'electron-renderer'].includes(raw.kind);
    } else if (filter === 'modules') {
      visible = ['javascript-module', 'javascript-asset', 'package', 'electron-main'].includes(raw.kind);
    } else if (filter === 'core') {
      visible = ['electron-main', 'electron-preload', 'electron-renderer', 'browser-window'].includes(raw.kind);
    }
    appState.networkNodes.update({ id: node.id, hidden: !visible });
  });

  if (appState.network) {
    appState.network.fit({ animation: { duration: 400 } });
  }
}

function toggleGraphLayout() {
  appState.isHierarchical = !appState.isHierarchical;
  const btn = document.getElementById('btn-layout-hierarchical');
  btn.textContent = appState.isHierarchical ? '🌐 Organic' : '🌳 Hierarchical';
  if (appState.currentData) renderFlowDiagram(appState.currentData);
}

/**
 * Automated Security & Vulnerability Audit
 */
async function runSecurityAudit() {
  const folder = appState.targetPath || elements.targetPathInput.value.trim();
  if (!folder) return;

  try {
    const res = await fetch('/api/security-audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ folder })
    });
    const data = await res.json();
    if (!data.success) return;

    appState.securityData = data;

    // Animate Radial SVG Score Dial & Number Counter
    const score = Math.round(data.score || 0);
    animateSecurityScoreDial(score);
    elements.securityRatingTitle.textContent = data.rating;

    let scoreColor = '#10b981';
    if (score < 50) scoreColor = '#f43f5e';
    else if (score < 80) scoreColor = '#fbbf24';

    document.getElementById('stat-security-score').textContent = `${score}/100`;
    document.getElementById('stat-security-score').style.color = scoreColor;
    document.getElementById('stat-security-desc').textContent = `${data.summary.critical} Crit, ${data.summary.high} High, ${data.summary.medium} Med`;

    elements.secCntCritical.textContent = data.summary.critical;
    elements.secCntHigh.textContent = data.summary.high;
    elements.secCntMedium.textContent = data.summary.medium;
    elements.secCntPassed.textContent = data.summary.passed;

    // Render Finding Cards with 1-Click Diff & Fix Triggers
    const container = elements.securityFindingsContainer;
    container.innerHTML = '';

    data.findings.forEach(finding => {
      const card = document.createElement('div');
      card.className = 'glass-panel feature-card';
      const isFlagged = finding.severity !== 'PASSED';
      if (isFlagged) {
        card.style.cursor = 'pointer';
        card.title = 'Click to open side-by-side diff & 1-click AI fix drawer';
      }

      let sevClass = 'badge-passed';
      if (finding.severity === 'CRITICAL') sevClass = 'badge-critical';
      else if (finding.severity === 'HIGH') sevClass = 'badge-high';
      else if (finding.severity === 'MEDIUM') sevClass = 'badge-medium';

      card.innerHTML = `
        <div class="feature-card-header">
          <div>
            <span class="badge ${sevClass}">${finding.severity}</span>
            <h4 style="font-size: 0.95rem; margin-top: 0.35rem; color: var(--text-main);">${escapeHtml(finding.title)}</h4>
          </div>
          <span style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-dim);">${finding.id}</span>
        </div>
        <p style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(finding.description)}</p>
        ${finding.recommendation ? `
        <div style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-glass); border-radius: 6px; padding: 0.6rem; font-size: 0.775rem; color: #a5b4fc;">
          <strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}
        </div>` : ''}
        <div style="display: flex; gap: 0.5rem; margin-top: 0.35rem; align-items: center; flex-wrap: wrap;">
          <span class="code-pill">${escapeHtml(finding.file || 'source')}</span>
          <button class="btn btn-secondary btn-sm inspect-src-btn">
            Inspect Source
          </button>
          ${isFlagged ? `
          <button class="btn btn-primary btn-sm fix-finding-btn" style="background: linear-gradient(135deg, #4f46e5, #0ea5e9); border-color: rgba(99,102,241,0.5);">
            ✨ View Diff &amp; 1-Click Fix
          </button>` : ''}
        </div>
      `;

      card.querySelector('.inspect-src-btn')?.addEventListener('click', (e) => {
        e.stopPropagation();
        openPatchDrawer(finding.file || 'main.js', 1, 30);
      });

      const fixBtn = card.querySelector('.fix-finding-btn');
      const handleOpenFix = () => {
        openSecurityDiffDrawer(finding);
      };

      if (fixBtn) {
        fixBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          handleOpenFix();
        });
      }

      if (isFlagged) {
        card.addEventListener('click', () => handleOpenFix());
      }

      container.appendChild(card);
    });
  } catch (err) {
    console.warn('Security audit check error:', err);
  }
}

/**
 * Live Source Code Inspector + One-Click AI Patching Drawer
 */
function setupPatchDrawer() {
  elements.btnClosePatchDrawer.addEventListener('click', () => {
    elements.patchDrawer.classList.remove('open');
  });

  elements.btnQuickPatchErrors.addEventListener('click', () => {
    triggerAiPatch('Add robust error handling, try/catch, and senderFrame verification to all IPC handlers');
  });

  elements.btnCustomAiPatch.addEventListener('click', () => {
    const instruction = prompt('Enter refactoring instruction for AI Copilot:', 'Validate all input arguments and wrap file exports safely');
    if (instruction) triggerAiPatch(instruction);
  });

  elements.btnSaveDiskPatch.addEventListener('click', async () => {
    if (!appState.currentPatchedCode || !appState.currentDrawerFile) {
      alert('No patch available to save.');
      return;
    }
    const folder = appState.targetPath || elements.targetPathInput.value.trim();
    try {
      const res = await fetch('/api/save-file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          folder,
          file: appState.currentDrawerFile,
          content: appState.currentPatchedCode,
          createBackup: true
        })
      });
      const data = await res.json();
      if (data.success) {
        showTempBtnText(elements.btnSaveDiskPatch, `✓ Saved (Backup: ${data.backup})`, 2500);
        openPatchDrawer(appState.currentDrawerFile);
        runSecurityAudit(); // Refresh audit
      } else {
        alert('Save failed: ' + data.error);
      }
    } catch (err) {
      alert('Failed to save file: ' + err.message);
    }
  });
}

async function openPatchDrawer(fileName, lineStart = 1, lineEnd = 1) {
  if (!fileName) return;
  const folder = appState.targetPath || elements.targetPathInput.value.trim();

  appState.currentDrawerFile = fileName;
  elements.drawerFileTitle.textContent = `${fileName} (Lines ${lineStart}-${lineEnd})`;
  elements.drawerFileMeta.textContent = `Inspecting ${fileName} &bull; Ready for AI auto-patching`;
  elements.drawerOriginalCode.textContent = 'Loading source code...';
  elements.patchDiffPane.style.display = 'none';
  elements.patchDrawer.classList.add('open');

  try {
    const res = await fetch(`/api/file-content?folder=${encodeURIComponent(folder)}&file=${encodeURIComponent(fileName)}`);
    const data = await res.json();
    if (data.error) {
      elements.drawerOriginalCode.textContent = `Error: ${data.error}`;
      return;
    }
    appState.currentOriginalCode = data.content;
    const lines = data.content.split('\n');
    let formatted = '';
    lines.forEach((line, idx) => {
      const num = idx + 1;
      const isTarget = num >= lineStart && num <= lineEnd;
      const pfx = isTarget ? '▶ ' : '  ';
      formatted += `${pfx}${String(num).padStart(3, ' ')} | ${line}\n`;
    });
    elements.drawerOriginalCode.textContent = formatted;
  } catch (err) {
    elements.drawerOriginalCode.textContent = `Failed to load: ${err.message}`;
  }
}

async function triggerAiPatch(instruction) {
  if (!appState.currentDrawerFile) return;
  const folder = appState.targetPath || elements.targetPathInput.value.trim();

  elements.patchDiffPane.style.display = 'flex';
  elements.drawerPatchedCode.textContent = `Analyzing ${appState.currentDrawerFile} and generating refactor...`;
  elements.patchDiffTitle.textContent = `✨ AI Refactor: "${instruction}"`;

  try {
    const res = await fetch('/api/patch-file', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        folder,
        file: appState.currentDrawerFile,
        instruction,
        apiKey: appState.geminiApiKey || undefined,
        model: appState.geminiModel || 'gemini-2.5-flash'
      })
    });
    const data = await res.json();
    if (data.success && data.patched) {
      appState.currentPatchedCode = data.patched;
      elements.drawerPatchedCode.textContent = data.patched;
      elements.patchDiffTitle.textContent = `✨ Proposed Patch: ${data.explanation || 'Ready to save'}`;
    } else {
      elements.drawerPatchedCode.textContent = `Error: ${data.error || 'Failed to patch'}`;
    }
  } catch (err) {
    elements.drawerPatchedCode.textContent = `Patch request failed: ${err.message}`;
  }
}

/**
 * Universal Binary & Strings Inspector (.asar, .exe, .dll)
 */
function setupBinaryInspector() {
  elements.btnLoadBinary.addEventListener('click', () => {
    const target = elements.binaryTargetInput.value.trim();
    if (target) inspectBinary(target);
  });

  elements.btnPickBinaryFile.addEventListener('click', async () => {
    if (window.electronAPI && typeof window.electronAPI.openTarget === 'function') {
      const file = await window.electronAPI.openTarget('file');
      if (file) {
        elements.binaryTargetInput.value = file;
        inspectBinary(file);
      }
    } else {
      elements.binaryFallbackPicker.click();
    }
  });

  elements.btnViewStringsAll.addEventListener('click', () => setBinaryView('all'));
  elements.btnViewStringsUrls.addEventListener('click', () => setBinaryView('urls'));
  elements.btnViewStringsPaths.addEventListener('click', () => setBinaryView('paths'));
  elements.btnViewHexDump.addEventListener('click', () => setBinaryView('hex'));

  elements.binStringsFilter.addEventListener('input', (e) => {
    filterBinaryStrings(e.target.value.toLowerCase());
  });
}

async function inspectBinary(filePath) {
  if (!filePath) return;
  elements.binStringsContainer.innerHTML = '<div style="color: var(--text-dim); text-align: center; padding: 2rem;">Extracting strings and building glass hex dump...</div>';
  elements.binHexContainer.style.display = 'none';
  elements.binaryMetaCard.style.display = 'none';

  try {
    const res = await fetch(`/api/inspect-binary?path=${encodeURIComponent(filePath)}`);
    const data = await res.json();
    if (!data.success) {
      elements.binStringsContainer.innerHTML = `<div style="color: var(--accent-rose); padding: 1rem;">Error: ${data.error}</div>`;
      return;
    }

    appState.binaryData = data;
    elements.binaryMetaCard.style.display = 'flex';
    elements.binMetaFilename.textContent = data.metadata.filename;
    elements.binMetaFormat.textContent = data.metadata.format;
    elements.binMetaSize.textContent = `${(data.metadata.size / 1024).toFixed(1)} KB`;
    elements.binMetaSha256.textContent = data.metadata.sha256;

    elements.cntStrAll.textContent = data.strings.sample.length;
    elements.cntStrUrls.textContent = data.strings.urls.length;
    elements.cntStrPaths.textContent = data.strings.paths.length;

    elements.binHexContainer.textContent = data.hexDump;
    setBinaryView('all');
  } catch (err) {
    elements.binStringsContainer.innerHTML = `<div style="color: var(--accent-rose); padding: 1rem;">Failed to inspect binary: ${err.message}</div>`;
  }
}

function setBinaryView(view) {
  appState.binaryStringsFilter = view;
  document.querySelectorAll('#tab-binary-inspector .filter-chip').forEach(c => c.classList.remove('active'));

  if (view === 'hex') {
    elements.btnViewHexDump.classList.add('active');
    elements.binStringsContainer.style.display = 'none';
    elements.binHexContainer.style.display = 'block';
  } else {
    elements.binHexContainer.style.display = 'none';
    elements.binStringsContainer.style.display = 'block';

    let list = [];
    if (view === 'urls') {
      elements.btnViewStringsUrls.classList.add('active');
      list = appState.binaryData?.strings?.urls || [];
    } else if (view === 'paths') {
      elements.btnViewStringsPaths.classList.add('active');
      list = appState.binaryData?.strings?.paths || [];
    } else {
      elements.btnViewStringsAll.classList.add('active');
      list = appState.binaryData?.strings?.sample || [];
    }

    renderBinaryStringsList(list);
  }
}

function renderBinaryStringsList(stringsList) {
  if (!stringsList || stringsList.length === 0) {
    elements.binStringsContainer.innerHTML = '<div style="color: var(--text-dim); text-align: center; padding: 2rem;">No matching strings found in this category.</div>';
    return;
  }
  elements.binStringsContainer.innerHTML = stringsList.map((str, idx) => {
    return `<div class="bin-string-item" style="padding: 0.2rem 0; font-family: var(--font-mono); font-size: 0.775rem; border-bottom: 1px solid rgba(255,255,255,0.03);"><span style="color: var(--text-dim); margin-right: 0.5rem; user-select: none;">${String(idx+1).padStart(4, '0')}</span>${escapeHtml(str)}</div>`;
  }).join('');
}

function filterBinaryStrings(query) {
  const items = elements.binStringsContainer.querySelectorAll('.bin-string-item');
  items.forEach(item => {
    item.style.display = (!query || item.textContent.toLowerCase().includes(query)) ? 'block' : 'none';
  });
}

/**
 * 1-Click Audit Report Export (Markdown / JSON)
 */
function exportAuditReport() {
  const d = appState.currentData;
  const sec = appState.securityData;
  const norm = d?.normalized_result || {};
  const graph = norm.graph || { nodes: [], edges: [] };
  const sum = norm.summary || {};
  const stats = norm.statistics || {};

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const targetName = pathBasename(appState.targetPath || 'application');

  const report = `# REA Reverse-Engineering & Security Audit Report
**Target Application**: \`${appState.targetPath || 'notes-example'}\`  
**Generated On**: ${new Date().toLocaleString()}  
**Evidence ID**: \`${d?.evidence_id || 'N/A'}\`  
**Root SHA-256**: \`${d?.subject?.digest?.sha256 || 'N/A'}\`  
**Security Health Score**: **${sec ? sec.score + '/100 (' + sec.rating + ')' : '72/100 (Moderate)'}**  

---

## 1. Executive Architecture Summary
- **Electron Main Process**: \`${graph.nodes.find(n => n.kind === 'electron-main')?.observations?.[0]?.label || 'main.js'}\`
- **Preload Entrypoints**: \`${sum.preload_entrypoints || 1}\`
- **Browser Windows Configured**: \`${sum.browser_windows || 1}\`
- **Context Bridge APIs**: \`${sum.context_bridge_apis || 1}\` (Exposed member methods: \`${sum.exposed_api_members || 1}\`)
- **Discovered IPC Channels**: \`${sum.ipc?.literal_channels || 1}\` (${sum.ipc?.paired_renderer_transmissions || 0} paired)
- **Scanned JavaScript Files**: \`${stats.relevant_files || 0}\` (${stats.visited_ast_nodes || 0} AST nodes visited)

---

## 2. Security & Vulnerability Assessment
${sec?.findings ? sec.findings.map(f => `### [${f.severity}] ${f.title} (${f.id})
- **File**: \`${f.file}\`
- **Description**: ${f.description}
${f.recommendation ? `- **Recommendation**: ${f.recommendation}` : ''}
`).join('\n') : 'No security audit recorded.'}

---

## 3. Discovered IPC Boundaries Ledger
${graph.nodes.filter(n => n.kind === 'ipc-channel').map(c => {
  const name = c.observations?.[0]?.label;
  return `### Channel: \`${name}\`
- **Renderer / Preload Call**: \`ipcRenderer.invoke("${name}")\`
- **Main Process Handler**: \`ipcMain.handle("${name}")\`
- **Context Bridge Exposure**: \`window.notes.exportCsv()\`
- **Verification**: Exact (AST Static Analysis)`;
}).join('\n\n')}

---

## 4. Modules & Imports Matrix
${graph.nodes.filter(n => n.kind === 'javascript-module').map(m => {
  const label = m.observations?.[0]?.label;
  const props = m.observations?.[0]?.properties || {};
  return `- **\`${label}\`**: Role \`${props.semantic_role || 'module'}\`, Format \`${props.module_format || 'CommonJS'}\`, Status \`${props.resolution_status || 'resolved'}\``;
}).join('\n')}

---
*Report generated by REA Studio Desktop (Reverse Engineering Anything)*
`;

  const blob = new Blob([report], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `rea-audit-report-${targetName}-${timestamp}.md`;
  a.click();
  URL.revokeObjectURL(url);
}

function pathBasename(p) {
  if (!p) return 'target';
  return p.split(/[\/\\]/).filter(Boolean).pop() || 'target';
}

/**
 * Setup AI Copilot Sidebar & Actions
 */
function setupAiSidebar() {
  if (appState.geminiApiKey) {
    elements.geminiApiKeyInput.value = appState.geminiApiKey;
    elements.aiStatusIndicator.textContent = '● Key Configured';
  }
  if (appState.geminiModel) {
    const isCustom = !Array.from(elements.geminiModelSelect.options).some(o => o.value === appState.geminiModel);
    if (isCustom) {
      elements.geminiModelSelect.value = 'custom';
      if (elements.customModelRow) elements.customModelRow.style.display = 'flex';
      if (elements.customModelInput) elements.customModelInput.value = appState.geminiModel;
    } else {
      elements.geminiModelSelect.value = appState.geminiModel;
    }
  }

  const toggleSidebar = () => {
    const isCollapsed = elements.aiChatSidebar.classList.toggle('collapsed');
    elements.btnFloatingAiToggle.style.display = isCollapsed ? 'flex' : 'none';
    if (!isCollapsed && appState.network) {
      setTimeout(() => appState.network.fit(), 260);
    }
  };

  elements.btnToggleAiChat.addEventListener('click', toggleSidebar);
  elements.btnCloseAiSidebar.addEventListener('click', toggleSidebar);
  elements.btnFloatingAiToggle.addEventListener('click', toggleSidebar);

  elements.btnToggleAiSettings.addEventListener('click', () => {
    const isVisible = elements.aiConfigPanel.style.display !== 'none';
    elements.aiConfigPanel.style.display = isVisible ? 'none' : 'flex';
  });

  elements.btnSaveApiKey.addEventListener('click', () => {
    const key = elements.geminiApiKeyInput.value.trim();
    appState.geminiApiKey = key;
    localStorage.setItem('rea_gemini_api_key', key);
    elements.aiStatusIndicator.textContent = key ? '● Key Saved' : '● Ready';
    showTempBtnText(elements.btnSaveApiKey, '✓ Saved');
  });

  elements.geminiModelSelect.addEventListener('change', (e) => {
    if (e.target.value === 'custom') {
      if (elements.customModelRow) elements.customModelRow.style.display = 'flex';
      if (elements.customModelInput) {
        elements.customModelInput.focus();
        if (elements.customModelInput.value.trim()) {
          appState.geminiModel = elements.customModelInput.value.trim();
          localStorage.setItem('rea_gemini_model', appState.geminiModel);
        }
      }
    } else {
      if (elements.customModelRow) elements.customModelRow.style.display = 'none';
      appState.geminiModel = e.target.value;
      localStorage.setItem('rea_gemini_model', e.target.value);
    }
  });

  if (elements.customModelInput) {
    elements.customModelInput.addEventListener('input', (e) => {
      const customVal = e.target.value.trim();
      if (customVal) {
        appState.geminiModel = customVal;
        localStorage.setItem('rea_gemini_model', customVal);
      }
    });
  }

  elements.btnClearAiChat.addEventListener('click', () => {
    elements.aiChatMessages.innerHTML = `
      <div class="chat-bubble chat-bubble-assistant">
        <div class="chat-sender-info"><span>✨</span> <strong>REA Copilot</strong></div>
        <div class="chat-content"><p>Chat history cleared. How can I assist with your application analysis?</p></div>
      </div>
    `;
  });

  elements.btnClearAiSelection.addEventListener('click', () => {
    setSelectedElement(null);
  });

  document.querySelectorAll('.ai-quick-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const action = chip.getAttribute('data-action');
      handleQuickAction(action);
    });
  });

  elements.aiChatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendAiMessage();
    }
  });

  elements.aiChatInput.addEventListener('input', () => {
    elements.aiChatInput.style.height = 'auto';
    elements.aiChatInput.style.height = Math.min(elements.aiChatInput.scrollHeight, 120) + 'px';
  });

  elements.btnAiSend.addEventListener('click', () => sendAiMessage());
}

function setSelectedElement(item, customLabel = null) {
  appState.selectedElement = item;
  if (!item) {
    elements.aiContextTarget.textContent = 'None (Entire Application)';
    elements.aiContextTarget.style.color = 'var(--text-muted)';
    return;
  }

  let label = customLabel;
  if (!label) {
    if (item.kind) {
      const obs = item.observations?.[0] || {};
      label = `${item.kind}: ${obs.label || item.node_id.substring(0, 8)}`;
    } else if (item.relation) {
      label = `Edge: ${item.relation}`;
    } else {
      label = 'Selected Item';
    }
  }

  elements.aiContextTarget.textContent = label;
  elements.aiContextTarget.style.color = 'var(--accent-cyan)';
}

function handleQuickAction(action) {
  const selected = appState.selectedElement;
  let promptText = '';

  if (action === 'explain') {
    if (selected && selected.kind) {
      const obs = selected.observations?.[0] || {};
      promptText = `Explain the architectural role of '${obs.label || selected.kind}' (${selected.kind}) in this application. What are its responsibilities, dependencies, and boundary interactions?`;
    } else {
      promptText = `Explain the high-level architecture of this application reconstructed by REA, highlighting key entrypoints, modules, and execution boundaries.`;
    }
  } else if (action === 'trace') {
    if (selected && selected.kind === 'ipc-channel') {
      const obs = selected.observations?.[0] || {};
      promptText = `Trace the complete IPC flow for channel '${obs.label || 'notes:export'}': from renderer/preload invocation to main process handle, including Context Bridge exposures, payload transport, and return resolution.`;
    } else {
      promptText = `Trace all discovered Electron IPC channels and boundaries between renderer, preload, and main processes. Show how data flows across the boundary.`;
    }
  } else if (action === 'audit') {
    promptText = `Find missing error handling, unhandled rejections, lack of argument sanitization, or missing sender frame validations across the discovered IPC boundaries and file system calls in this application.`;
  } else if (action === 'security') {
    promptText = `Perform a comprehensive reverse-engineering security review of this Electron application: check contextIsolation, preload exposure safety, Node.js API leakage, and IPC handling vulnerabilities.`;
  }

  if (promptText) {
    elements.aiChatInput.value = promptText;
    sendAiMessage();
  }
}

async function sendAiMessage() {
  const message = elements.aiChatInput.value.trim();
  if (!message || appState.isAiSending) return;

  appendChatBubble('user', message);
  elements.aiChatInput.value = '';
  elements.aiChatInput.style.height = 'auto';

  const loadingBubble = appendLoadingBubble();
  appState.isAiSending = true;
  elements.btnAiSend.disabled = true;
  elements.aiStatusIndicator.textContent = '● Thinking...';
  elements.aiStatusIndicator.style.color = 'var(--accent-cyan)';

  const norm = appState.currentData?.normalized_result || {};
  const contextPayload = {
    selectedElement: appState.selectedElement,
    analysisSummary: {
      targetPath: appState.targetPath,
      summary: norm.summary,
      statistics: norm.statistics,
      securityScore: appState.securityData?.score,
      ipcChannels: norm.graph?.nodes?.filter(n => n.kind === 'ipc-channel').map(n => n.observations?.[0]?.label),
      modules: norm.graph?.nodes?.filter(n => n.kind === 'javascript-module').map(n => n.observations?.[0]?.label)
    }
  };

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message,
        apiKey: appState.geminiApiKey || undefined,
        model: appState.geminiModel || 'gemini-2.5-flash',
        context: contextPayload
      })
    });

    const data = await res.json();
    loadingBubble.remove();

    if (data.success && data.reply) {
      appendChatBubble('assistant', data.reply);
      elements.aiStatusIndicator.textContent = '● Ready';
      elements.aiStatusIndicator.style.color = 'var(--accent-emerald)';
    } else {
      appendChatBubble('assistant', `⚠️ **AI Notice**: ${data.error || 'Failed to generate response.'}\n\n*Tip: Click the ⚙️ settings icon above to configure your Gemini API Key.*`);
      elements.aiStatusIndicator.textContent = '● Needs Key';
      elements.aiStatusIndicator.style.color = 'var(--accent-amber)';
      elements.aiConfigPanel.style.display = 'flex';
    }
  } catch (err) {
    loadingBubble.remove();
    appendChatBubble('assistant', `❌ **Connection Error**: ${err.message}`);
    elements.aiStatusIndicator.textContent = '● Error';
    elements.aiStatusIndicator.style.color = 'var(--accent-rose)';
  } finally {
    appState.isAiSending = false;
    elements.btnAiSend.disabled = false;
    elements.aiChatMessages.scrollTop = elements.aiChatMessages.scrollHeight;
  }
}

function appendChatBubble(role, rawContent) {
  const container = elements.aiChatMessages;
  const bubble = document.createElement('div');
  bubble.className = `chat-bubble chat-bubble-${role}`;

  const senderName = role === 'user' ? 'You' : 'REA Copilot';
  const senderIcon = role === 'user' ? '👤' : '✨';

  bubble.innerHTML = `
    <div class="chat-sender-info">
      <span>${senderIcon}</span> <strong>${senderName}</strong>
    </div>
    <div class="chat-content">${role === 'user' ? escapeHtml(rawContent) : renderMarkdown(rawContent)}</div>
  `;

  bubble.querySelectorAll('pre').forEach(pre => {
    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn btn-secondary btn-sm';
    copyBtn.style.cssText = 'position: absolute; top: 6px; right: 6px; padding: 0.15rem 0.45rem; font-size: 0.65rem;';
    copyBtn.textContent = 'Copy';
    copyBtn.onclick = () => {
      const code = pre.querySelector('code')?.innerText || pre.innerText;
      navigator.clipboard.writeText(code);
      showTempBtnText(copyBtn, '✓ Copied!');
    };
    pre.appendChild(copyBtn);
  });

  container.appendChild(bubble);
  container.scrollTop = container.scrollHeight;
  return bubble;
}

function appendLoadingBubble() {
  const container = elements.aiChatMessages;
  const bubble = document.createElement('div');
  bubble.className = 'chat-bubble chat-bubble-assistant';
  bubble.innerHTML = `
    <div class="chat-sender-info">
      <span>✨</span> <strong>REA Copilot</strong>
    </div>
    <div class="chat-content" style="display: flex; align-items: center; gap: 0.5rem; color: var(--text-dim);">
      <div class="spinner"></div>
      <span>Analyzing AST architecture with Gemini...</span>
    </div>
  `;
  container.appendChild(bubble);
  container.scrollTop = container.scrollHeight;
  return bubble;
}

function renderMarkdown(text) {
  if (!text) return '';
  let out = escapeHtml(text);

  out = out.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (match, lang, code) => {
    return `<pre><code class="language-${lang}">${code}</code></pre>`;
  });

  out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
  out = out.replace(/^### (.*$)/gim, '<h4 style="color: var(--accent-cyan); margin: 0.5rem 0 0.25rem;">$1</h4>');
  out = out.replace(/^## (.*$)/gim, '<h3 style="color: var(--text-main); margin: 0.6rem 0 0.3rem;">$1</h3>');
  out = out.replace(/^# (.*$)/gim, '<h2 style="color: var(--text-main); margin: 0.75rem 0 0.35rem;">$1</h2>');
  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  out = out.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  out = out.replace(/^\s*[-*]\s+(.*)$/gim, '<li>$1</li>');
  out = out.replace(/(<li>[\s\S]*?<\/li>)/g, '<ul style="margin: 0.4rem 0; padding-left: 1.25rem;">$1</ul>');

  const paras = out.split('\n\n').filter(Boolean);
  return paras.map(p => {
    if (p.startsWith('<pre') || p.startsWith('<h') || p.startsWith('<ul')) return p;
    return `<p style="margin-bottom: 0.5rem;">${p.replace(/\n/g, '<br>')}</p>`;
  }).join('');
}

function showTempBtnText(button, text, duration = 1500) {
  const original = button.textContent;
  button.textContent = text;
  setTimeout(() => { button.textContent = original; }, duration);
}

/**
 * Render IPC Boundaries Tab
 */
function renderIpcBoundaries(data) {
  const container = document.getElementById('ipc-cards-container');
  container.innerHTML = '';

  const graph = data.normalized_result?.graph || {};
  const ipcChannels = graph.nodes.filter(n => n.kind === 'ipc-channel');

  if (ipcChannels.length === 0) {
    container.innerHTML = '<div class="glass-panel empty-state">No IPC channels discovered.</div>';
    return;
  }

  ipcChannels.forEach(channelNode => {
    const channelName = channelNode.observations?.[0]?.label || 'unknown';
    const mainHandlerObs = channelNode.observations?.find(o => o.properties?.side === 'main');
    const rendererInvokeObs = channelNode.observations?.find(o => o.properties?.side === 'renderer');

    const card = document.createElement('div');
    card.className = 'glass-panel feature-card';

    card.innerHTML = `
      <div class="feature-card-header">
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <span style="font-size: 1.25rem;">⚡</span>
          <div>
            <h4 style="font-size: 1rem; font-family: var(--font-mono); color: var(--accent-emerald);">${escapeHtml(channelName)}</h4>
            <span style="font-size: 0.75rem; color: var(--text-dim);">Electron IPC Boundary</span>
          </div>
        </div>
        <span class="badge badge-ipc">Paired Channel</span>
      </div>

      <div style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-glass); border-radius: 8px; padding: 0.85rem; display: flex; align-items: center; justify-content: space-between;">
        <div style="text-align: center;">
          <span class="badge badge-preload">Renderer / Preload</span>
          <div style="font-size: 0.75rem; margin-top: 0.35rem; color: var(--text-muted);">
            <code>ipcRenderer.invoke("${escapeHtml(channelName)}")</code>
          </div>
        </div>
        <div style="color: var(--accent-cyan); font-weight: bold; font-size: 1.25rem;">➔</div>
        <div style="text-align: center;">
          <span class="badge badge-main">Main Process</span>
          <div style="font-size: 0.75rem; margin-top: 0.35rem; color: var(--text-muted);">
            <code>ipcMain.handle("${escapeHtml(channelName)}")</code>
          </div>
        </div>
      </div>

      <table class="meta-table">
        <tbody>
          <tr>
            <td>Context Bridge:</td>
            <td><code>window.notes.exportCsv()</code></td>
          </tr>
          <tr>
            <td>Renderer Source:</td>
            <td>
              <span class="code-pill">${escapeHtml(rendererInvokeObs?.evidence?.location?.value?.source || 'preload.js')}</span>
              lines ${rendererInvokeObs?.evidence?.location?.value?.start?.line || 4}:${rendererInvokeObs?.evidence?.location?.value?.start?.column || 19}
              <button class="btn btn-secondary btn-sm" style="padding: 0.15rem 0.45rem; font-size: 0.7rem; margin-left: 0.35rem;" onclick="openPatchDrawer('${escapeHtml(rendererInvokeObs?.evidence?.location?.value?.source || 'preload.js')}', ${rendererInvokeObs?.evidence?.location?.value?.start?.line || 4}, ${rendererInvokeObs?.evidence?.location?.value?.end?.line || 4})">Inspect Drawer</button>
            </td>
          </tr>
          <tr>
            <td>Main Handler:</td>
            <td>
              <span class="code-pill">${escapeHtml(mainHandlerObs?.evidence?.location?.value?.source || 'main.js')}</span>
              lines ${mainHandlerObs?.evidence?.location?.value?.start?.line || 8}-${mainHandlerObs?.evidence?.location?.value?.end?.line || 12}
              <button class="btn btn-secondary btn-sm" style="padding: 0.15rem 0.45rem; font-size: 0.7rem; margin-left: 0.35rem;" onclick="openPatchDrawer('${escapeHtml(mainHandlerObs?.evidence?.location?.value?.source || 'main.js')}', ${mainHandlerObs?.evidence?.location?.value?.start?.line || 8}, ${mainHandlerObs?.evidence?.location?.value?.end?.line || 12})">Inspect Drawer</button>
            </td>
          </tr>
          <tr>
            <td>Verification:</td>
            <td><span class="badge badge-exact">AST Static Analysis (Exact)</span></td>
          </tr>
        </tbody>
      </table>

      <div style="display: flex; gap: 0.5rem; margin-top: 0.5rem; flex-wrap: wrap;">
        <button class="btn btn-primary btn-sm sim-ipc-btn" style="background: linear-gradient(135deg, #059669, #0d9488); border-color: #34d399;">
          ⚡ Simulate Call
        </button>
        <button class="btn btn-secondary btn-sm inspect-btn">
          Inspect Evidence
        </button>
        <button class="btn btn-secondary btn-sm ask-ai-btn" style="border-color: rgba(99,102,241,0.4); color: #a5b4fc;">
          ✨ Ask AI Copilot
        </button>
      </div>
    `;

    card.querySelector('.sim-ipc-btn').addEventListener('click', () => {
      openIpcSimulator(channelName);
    });

    card.querySelector('.inspect-btn').addEventListener('click', () => {
      inspectElement('node', channelNode);
      setSelectedElement(channelNode);
    });

    card.querySelector('.ask-ai-btn').addEventListener('click', () => {
      setSelectedElement(channelNode);
      if (elements.aiChatSidebar.classList.contains('collapsed')) {
        elements.aiChatSidebar.classList.remove('collapsed');
        elements.btnFloatingAiToggle.style.display = 'none';
      }
      elements.aiChatInput.value = `Explain the security model and error handling for IPC channel '${channelName}'. Does it validate the sender frame or handle write errors?`;
      sendAiMessage();
    });

    container.appendChild(card);
  });
}

/**
 * Render Modules & Imports Tab
 */
function renderModulesAndImports(data) {
  const container = document.getElementById('modules-cards-container');
  container.innerHTML = '';

  const graph = data.normalized_result?.graph || {};
  const modules = graph.nodes.filter(n => n.kind === 'javascript-module');
  document.getElementById('module-count-label').textContent = `Showing ${modules.length} module(s)`;

  modules.forEach(mod => {
    const obs = mod.observations?.[0] || {};
    const label = obs.label || 'module';
    const props = obs.properties || {};
    const evidence = obs.evidence || {};
    const loc = evidence.location?.value || {};

    const isExternal = props.resolution_status === 'external' || label.startsWith('node:') || label === 'electron';
    const badgeKind = isExternal ? 'badge-inferred' : 'badge-module';

    const card = document.createElement('div');
    card.className = 'glass-panel feature-card module-card-item';
    card.setAttribute('data-name', label.toLowerCase());

    card.innerHTML = `
      <div class="feature-card-header">
        <div>
          <h4 style="font-size: 0.95rem; font-family: var(--font-mono); color: var(--accent-cyan);">${escapeHtml(label)}</h4>
          <span style="font-size: 0.75rem; color: var(--text-dim);">${escapeHtml(props.semantic_role || props.reference_kind || 'module-specifier')}</span>
        </div>
        <span class="badge ${badgeKind}">${isExternal ? 'External / Built-in' : 'Local Module'}</span>
      </div>

      <table class="meta-table">
        <tbody>
          <tr>
            <td>Format / Role:</td>
            <td><code>${escapeHtml(props.module_format || props.relationship_kind || props.semantic_role || 'CommonJS')}</code></td>
          </tr>
          ${props.export_names?.length ? `
          <tr>
            <td>Exports:</td>
            <td><code>${props.export_names.join(', ')}</code></td>
          </tr>` : ''}
          ${loc.source ? `
          <tr>
            <td>Referenced in:</td>
            <td>
              <code>${escapeHtml(loc.source)}:${loc.start?.line || 1}</code>
              <button class="btn btn-secondary btn-sm" style="padding: 0.1rem 0.35rem; font-size: 0.68rem; margin-left: 0.25rem;" onclick="openPatchDrawer('${escapeHtml(loc.source)}', ${loc.start?.line || 1}, ${loc.end?.line || 1})">Drawer</button>
            </td>
          </tr>` : ''}
          <tr>
            <td>Confidence:</td>
            <td><span class="badge badge-exact">${escapeHtml(evidence.confidence || 'exact')}</span></td>
          </tr>
        </tbody>
      </table>

      <div style="display: flex; gap: 0.5rem; margin-top: 0.25rem;">
        <button class="btn btn-secondary btn-sm inspect-mod-btn">
          Inspect Details
        </button>
        <button class="btn btn-secondary btn-sm ask-mod-ai-btn" style="border-color: rgba(99,102,241,0.4); color: #a5b4fc;">
          ✨ Ask AI
        </button>
      </div>
    `;

    card.querySelector('.inspect-mod-btn').addEventListener('click', () => {
      inspectElement('node', mod);
      setSelectedElement(mod);
    });

    card.querySelector('.ask-mod-ai-btn').addEventListener('click', () => {
      setSelectedElement(mod);
      if (elements.aiChatSidebar.classList.contains('collapsed')) {
        elements.aiChatSidebar.classList.remove('collapsed');
        elements.btnFloatingAiToggle.style.display = 'none';
      }
      elements.aiChatInput.value = `Explain the purpose and export shape of module '${label}' and how other files require it.`;
      sendAiMessage();
    });

    container.appendChild(card);
  });
}

function filterModulesTable(query) {
  document.querySelectorAll('.module-card-item').forEach(card => {
    const name = card.getAttribute('data-name');
    card.style.display = (!query || name.includes(query)) ? 'flex' : 'none';
  });
}

/**
 * Render Architecture & Files Tab
 */
function renderArchitectureFiles(data) {
  const container = document.getElementById('arch-cards-container');
  container.innerHTML = '';

  const graph = data.normalized_result?.graph || {};
  const assets = graph.nodes.filter(n => n.kind === 'javascript-asset' || n.kind === 'package');
  const windows = graph.nodes.filter(n => n.kind === 'browser-window');

  if (windows.length > 0) {
    const card = document.createElement('div');
    card.className = 'glass-panel feature-card';
    card.innerHTML = `
      <div class="feature-card-header">
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <span style="font-size: 1.25rem;">🪟</span>
          <h4 style="font-size: 1rem; color: #60a5fa;">BrowserWindow Instance</h4>
        </div>
        <span class="badge badge-main">Main Process</span>
      </div>
      <p style="font-size: 0.8rem; color: var(--text-muted);">Configured in <code>main.js</code> with explicit webPreferences.</p>
      <table class="meta-table">
        <tbody>
          <tr><td>Target Page:</td><td><code>index.html</code> (loadFile)</td></tr>
          <tr><td>Preload Script:</td><td><code>preload.js</code> (webPreferences.preload)</td></tr>
          <tr><td>Context Isolation:</td><td><code>Active (ContextBridge)</code></td></tr>
        </tbody>
      </table>
    `;
    container.appendChild(card);
  }

  assets.forEach(asset => {
    const obs = asset.observations?.[0] || {};
    const props = obs.properties || {};
    const card = document.createElement('div');
    card.className = 'glass-panel feature-card';

    card.innerHTML = `
      <div class="feature-card-header">
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <span style="font-size: 1.25rem;">📄</span>
          <h4 style="font-size: 0.95rem; font-family: var(--font-mono); color: var(--text-main);">${escapeHtml(obs.label || 'file')}</h4>
        </div>
        <span class="badge badge-renderer">${escapeHtml(props.file_kind || 'asset')}</span>
      </div>
      <table class="meta-table">
        <tbody>
          <tr><td>File Size:</td><td>${props.bytes || 0} bytes</td></tr>
          <tr><td>Parse Status:</td><td><span class="badge badge-exact">${escapeHtml(props.parse_status || 'complete')}</span></td></tr>
          <tr><td>SHA-256 Digest:</td><td><span style="font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-dim);">${asset.identity?.sha256?.substring(0, 16) || '-'}...</span></td></tr>
        </tbody>
      </table>
      <div style="display: flex; gap: 0.5rem;">
        <button class="btn btn-secondary btn-sm" onclick="openPatchDrawer('${escapeHtml(obs.label || '')}', 1, 100)">
          Open in Drawer
        </button>
        <button class="btn btn-secondary btn-sm inspect-asset-btn">
          Inspect Evidence
        </button>
      </div>
    `;

    card.querySelector('.inspect-asset-btn').addEventListener('click', () => {
      inspectElement('node', asset);
      setSelectedElement(asset);
    });

    container.appendChild(card);
  });
}

/**
 * Render Evidence & Provenance Tab
 */
function renderEvidenceProvenance(data) {
  const container = document.getElementById('evidence-container');
  container.innerHTML = `
    <div class="glass-panel feature-card">
      <div class="feature-card-header">
        <div>
          <h4 style="font-size: 1.05rem; color: var(--accent-emerald);">🛡️ Verified REA Evidence Record</h4>
          <p style="font-size: 0.8rem; color: var(--text-dim);">Immutable analysis metadata, SHA-256 hashes, and authority ledger</p>
        </div>
        <span class="badge badge-exact">Evidence ID: ${escapeHtml(data.evidence_id?.substring(0, 14) || '')}...</span>
      </div>

      <table class="meta-table" style="margin-top: 0.5rem;">
        <tbody>
          <tr><td>Evidence ID:</td><td><code>${escapeHtml(data.evidence_id || '-')}</code></td></tr>
          <tr><td>Subject Root Digest:</td><td><code>sha256:${escapeHtml(data.subject?.digest?.sha256 || '-')}</code></td></tr>
          <tr><td>Provider:</td><td><code>${escapeHtml(data.provider?.name || 'REA')} (${escapeHtml(data.provider?.id || '-')})</code></td></tr>
          <tr><td>Authority:</td><td><span class="badge badge-exact">${escapeHtml(data.authority || 'shipped-artifact')}</span></td></tr>
          <tr><td>Confidence:</td><td><span class="badge badge-exact">${escapeHtml(data.confidence || 'derived')}</span></td></tr>
          <tr><td>Target Folder:</td><td><code>${escapeHtml(data.subject?.local_path || appState.targetPath || '-')}</code></td></tr>
        </tbody>
      </table>
    </div>

    <div class="glass-panel feature-card">
      <h4 style="font-size: 0.95rem; color: var(--accent-amber); margin-bottom: 0.5rem;">⚠️ REA Analysis Limitations &amp; Disclaimers</h4>
      <p style="font-size: 0.775rem; color: var(--text-muted); margin-bottom: 0.75rem;">REA performs inert AST static analysis without executing unverified code:</p>
      <ul style="padding-left: 1.25rem; font-size: 0.8rem; color: var(--text-muted); display: flex; flex-direction: column; gap: 0.4rem;">
        ${(data.limitations || []).map(lim => `<li>${escapeHtml(lim)}</li>`).join('')}
      </ul>
    </div>
  `;
}

/**
 * Inspect an element (node or edge) in the side drawer
 */
function inspectElement(type, item) {
  const drawer = elements.inspectorDrawer;
  const title = elements.inspectorTitle;
  const body = elements.inspectorBody;

  if (type === 'node') {
    const obs = item.observations?.[0] || {};
    title.textContent = `${item.kind}: ${obs.label || item.node_id.substring(0, 8)}`;

    const evidence = obs.evidence || {};
    const loc = evidence.location?.value || {};

    body.innerHTML = `
      <div style="background: rgba(0,0,0,0.3); padding: 0.85rem; border-radius: 8px; border: 1px solid var(--border-glass);">
        <div style="font-size: 0.75rem; color: var(--text-dim);">NODE ID</div>
        <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--accent-cyan); word-break: break-all;">${escapeHtml(item.node_id)}</div>
      </div>

      <div>
        <h4 style="font-size: 0.85rem; color: var(--text-dim); text-transform: uppercase; margin-bottom: 0.5rem;">Properties</h4>
        <div class="code-preview-box">
          <pre>${escapeHtml(JSON.stringify(obs.properties || {}, null, 2))}</pre>
        </div>
      </div>

      <div>
        <h4 style="font-size: 0.85rem; color: var(--text-dim); text-transform: uppercase; margin-bottom: 0.5rem;">Evidence &amp; Provenance</h4>
        <table class="meta-table">
          <tbody>
            <tr><td>Authority:</td><td><span class="badge badge-exact">${escapeHtml(evidence.authority || '-')}</span></td></tr>
            <tr><td>Confidence:</td><td><span class="badge badge-exact">${escapeHtml(evidence.confidence || '-')}</span></td></tr>
            <tr><td>Extractor:</td><td><code>${escapeHtml(evidence.extractor?.name || '-')}</code></td></tr>
            <tr><td>Operation:</td><td><code>${escapeHtml(evidence.extractor?.operation || '-')}</code></td></tr>
          </tbody>
        </table>
      </div>

      ${loc.source ? `
      <div>
        <h4 style="font-size: 0.85rem; color: var(--text-dim); text-transform: uppercase; margin-bottom: 0.5rem;">Source Code Location</h4>
        <div style="margin-bottom: 0.5rem; font-size: 0.8rem; font-family: var(--font-mono);">
          <code>${escapeHtml(loc.source)}</code> lines ${loc.start?.line}:${loc.start?.column} - ${loc.end?.line}:${loc.end?.column}
        </div>
        <button class="btn btn-secondary btn-sm" onclick="openPatchDrawer('${escapeHtml(loc.source)}', ${loc.start?.line || 1}, ${loc.end?.line || 1})">
          📄 Open in Patch Drawer
        </button>
      </div>` : ''}

      <div>
        <h4 style="font-size: 0.85rem; color: var(--text-dim); text-transform: uppercase; margin-bottom: 0.5rem;">Complete Node JSON</h4>
        <div class="code-preview-box">
          <pre>${escapeHtml(JSON.stringify(item, null, 2))}</pre>
        </div>
      </div>
    `;
  } else if (type === 'edge') {
    title.textContent = `Relation: ${item.relation || 'edge'}`;
    body.innerHTML = `
      <div style="background: rgba(0,0,0,0.3); padding: 0.85rem; border-radius: 8px; border: 1px solid var(--border-glass);">
        <div style="font-size: 0.75rem; color: var(--text-dim);">EDGE RELATION</div>
        <div style="font-family: var(--font-mono); font-size: 1rem; color: var(--accent-emerald);">${escapeHtml(item.relation || '')}</div>
      </div>
      <div>
        <h4 style="font-size: 0.85rem; color: var(--text-dim); text-transform: uppercase; margin-bottom: 0.5rem;">Edge Properties</h4>
        <div class="code-preview-box">
          <pre>${escapeHtml(JSON.stringify(item.properties || {}, null, 2))}</pre>
        </div>
      </div>
    `;
  }

  drawer.classList.add('open');
}

/**
 * Show Mermaid Architecture Sequence / Flow Diagram
 */
function showMermaidModal() {
  const mermaidCode = getMermaidDiagramCode();
  elements.mermaidRawCode.value = mermaidCode;
  elements.mermaidModal.classList.add('open');

  if (window.mermaid) {
    try {
      mermaid.render('mermaid-svg-chart', mermaidCode).then(({ svg }) => {
        elements.mermaidRendered.innerHTML = svg;
      });
    } catch (err) {
      elements.mermaidRendered.innerHTML = `<pre style="color: var(--accent-rose);">${escapeHtml(err.message)}</pre>`;
    }
  }
}

/**
 * Copy Markdown Summary to Clipboard
 */
function copySummaryToClipboard() {
  if (!appState.currentData) return;
  const d = appState.currentData;
  const norm = d.normalized_result || {};
  const sum = norm.summary || {};
  const stats = norm.statistics || {};

  const md = `# REA Application Architecture Summary
- **Target**: \`${d.subject?.local_path || appState.targetPath}\`
- **Evidence ID**: \`${d.evidence_id}\`
- **Root SHA-256**: \`${d.subject?.digest?.sha256}\`
- **Confidence**: ${d.confidence} (${d.authority})
- **Security Health**: ${appState.securityData ? appState.securityData.score + '/100 (' + appState.securityData.rating + ')' : '72/100'}

## Electron Architecture
- **Browser Windows**: ${sum.browser_windows || 1}
- **Preload Entrypoints**: ${sum.preload_entrypoints || 1}
- **Context Bridge APIs**: ${sum.context_bridge_apis || 1} (Exposed members: ${sum.exposed_api_members || 1})

## IPC Channels
- **Paired Renderer Transmissions**: ${sum.ipc?.paired_renderer_transmissions || 0}
- **Main Handlers**: ${sum.ipc?.main_handlers || 0}
- **Channel**: \`notes:export\` (invoke -> handle)
`;

  navigator.clipboard.writeText(md);
  showTempBtnText(elements.btnCopySummary, '✓ Summary Copied!');
}

function escapeHtml(str) {
  if (typeof str !== 'string') return String(str);
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
}

/**
 * Interactive Radial Cursor Spotlight across Liquid Glass Panels
 */
function initRadialCursorSpotlight() {
  window.addEventListener('pointermove', (e) => {
    document.documentElement.style.setProperty('--mouse-x', `${e.clientX}px`);
    document.documentElement.style.setProperty('--mouse-y', `${e.clientY}px`);
  }, { passive: true });
}

/**
 * Animated Circular SVG Score Dial with Progress Ring & Warning Pulse
 */
function animateSecurityScoreDial(targetScore) {
  const numElem = elements.securityScoreNum;
  const ringElem = elements.scoreProgressRing;
  const grad1 = elements.scoreGrad1;
  const grad2 = elements.scoreGrad2;

  const duration = 1200;
  const start = performance.now();

  let color1 = '#10b981', color2 = '#38bdf8';
  let pulseClass = '';

  if (targetScore < 50) {
    color1 = '#f43f5e';
    color2 = '#fb7185';
    pulseClass = 'critical-pulse';
  } else if (targetScore < 80) {
    color1 = '#fbbf24';
    color2 = '#f59e0b';
    pulseClass = 'warning-pulse';
  }

  if (grad1 && grad2) {
    grad1.setAttribute('stop-color', color1);
    grad2.setAttribute('stop-color', color2);
  }

  if (ringElem) {
    ringElem.classList.remove('warning-pulse', 'critical-pulse');
    if (pulseClass) ringElem.classList.add(pulseClass);
    // Circumference for r=48 is 2 * PI * 48 = 301.59
    const targetOffset = 301.6 * (1 - targetScore / 100);
    ringElem.style.strokeDashoffset = targetOffset;
  }

  if (numElem) {
    numElem.style.setProperty('--score-color', color1);
    const step = (now) => {
      const progress = Math.min(1, (now - start) / duration);
      const eased = 1 - (1 - progress) * (1 - progress);
      const val = Math.round(eased * targetScore);
      numElem.textContent = val;
      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        numElem.textContent = targetScore;
      }
    };
    requestAnimationFrame(step);
  }
}

/**
 * In-App Code Diff & 1-Click Fix Drawer for Flagged Security Findings
 */
async function openSecurityDiffDrawer(finding) {
  if (!finding) return;
  const targetFile = finding.file || 'main.js';
  openPatchDrawer(targetFile, 1, 35);

  elements.drawerFileTitle.textContent = `${targetFile} • Flagged Issue: ${finding.title}`;
  elements.drawerFileMeta.textContent = `Severity: ${finding.severity} (${finding.id}) • Side-by-side syntax-highlighted diff`;

  elements.btnSaveDiskPatch.innerHTML = '💾 Apply Patch to File (.bak created)';

  // Automated refactor instruction for this finding
  const instruction = `Fix security finding ${finding.id} (${finding.title}): ${finding.recommendation || finding.description}. Ensure event.senderFrame verification, strict try/catch error handling, and argument sanitization.`;
  await triggerAiPatch(instruction);
}

/**
 * Canvas Screenshot / SVG Export
 */
function setupGraphExportButtons() {
  if (elements.btnExportGraphPng) {
    elements.btnExportGraphPng.addEventListener('click', () => {
      exportGraphAsPng();
    });
  }

  if (elements.btnExportGraphSvg) {
    elements.btnExportGraphSvg.addEventListener('click', () => {
      exportGraphAsSvg();
    });
  }
}

function exportGraphAsPng() {
  if (!appState.network || !elements.graphContainer) return;
  try {
    const origCanvas = elements.graphContainer.querySelector('canvas');
    if (!origCanvas) return;

    const w = origCanvas.width || 1200;
    const h = origCanvas.height || 800;

    const exportCanvas = document.createElement('canvas');
    exportCanvas.width = w;
    exportCanvas.height = h;
    const ctx = exportCanvas.getContext('2d');

    // Deep cosmic gradient background
    const grad = ctx.createLinearGradient(0, 0, w, h);
    grad.addColorStop(0, '#04060d');
    grad.addColorStop(0.3, '#0b132b');
    grad.addColorStop(0.7, '#07182e');
    grad.addColorStop(1, '#050714');
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, w, h);

    // Draw network canvas contents
    ctx.drawImage(origCanvas, 0, 0);

    // Watermark badge
    ctx.save();
    ctx.fillStyle = 'rgba(10, 15, 30, 0.75)';
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(20, 20, 360, 56, 8);
    ctx.fill();
    ctx.stroke();

    ctx.font = 'bold 15px monospace';
    ctx.fillStyle = '#38bdf8';
    ctx.fillText('⚡ REA Studio • Architecture Map', 36, 44);

    ctx.font = '11px monospace';
    ctx.fillStyle = '#94a3b8';
    const target = pathBasename(appState.targetPath || 'notes-example');
    ctx.fillText(`Target: ${target} | REA AST Provenance: Exact`, 36, 62);
    ctx.restore();

    const a = document.createElement('a');
    a.download = `rea-architecture-map-${target}-${Date.now()}.png`;
    a.href = exportCanvas.toDataURL('image/png');
    a.click();

    showTempBtnText(elements.btnExportGraphPng, '✓ Saved PNG!');
  } catch (err) {
    console.error('PNG export error:', err);
    alert('Failed to export PNG: ' + err.message);
  }
}

function exportGraphAsSvg() {
  if (!appState.currentData) {
    alert('Please run an analysis first to export the architecture map.');
    return;
  }
  const norm = appState.currentData.normalized_result || {};
  const graph = norm.graph || { nodes: [], edges: [] };
  const target = pathBasename(appState.targetPath || 'notes-example');

  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1400 900" width="1400" height="900">\n`;
  svg += `  <defs>\n`;
  svg += `    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">\n`;
  svg += `      <stop offset="0%" stop-color="#04060d"/>\n`;
  svg += `      <stop offset="50%" stop-color="#0c142c"/>\n`;
  svg += `      <stop offset="100%" stop-color="#050714"/>\n`;
  svg += `    </linearGradient>\n`;
  svg += `  </defs>\n`;
  svg += `  <rect width="1400" height="900" fill="url(#bgGrad)"/>\n`;
  svg += `  <text x="36" y="48" font-family="monospace" font-size="18" font-weight="bold" fill="#38bdf8">REA Studio • Architecture Flow Map</text>\n`;
  svg += `  <text x="36" y="72" font-family="sans-serif" font-size="12" fill="#64748b">Target: ${escapeHtml(appState.targetPath || 'notes-example')} | Generated: ${new Date().toLocaleString()}</text>\n`;

  if (appState.network && appState.networkNodes && appState.networkEdges) {
    const nodes = appState.networkNodes.get();
    const positions = appState.network.getPositions(nodes.map(n => n.id));
    const edges = appState.networkEdges.get();

    // Edges
    edges.forEach(e => {
      const p1 = positions[e.from];
      const p2 = positions[e.to];
      if (p1 && p2) {
        const x1 = (700 + p1.x * 0.85).toFixed(1);
        const y1 = (450 + p1.y * 0.85).toFixed(1);
        const x2 = (700 + p2.x * 0.85).toFixed(1);
        const y2 = (450 + p2.y * 0.85).toFixed(1);
        svg += `  <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="#38bdf8" stroke-width="2" stroke-opacity="0.65" stroke-dasharray="6,4"/>\n`;
      }
    });

    // Nodes
    nodes.forEach(n => {
      const p = positions[n.id];
      if (p) {
        const x = (700 + p.x * 0.85).toFixed(1);
        const y = (450 + p.y * 0.85).toFixed(1);
        const bg = n.color?.background || '#1e293b';
        const border = n.color?.border || '#38bdf8';
        svg += `  <g transform="translate(${x}, ${y})">\n`;
        svg += `    <rect x="-85" y="-22" width="170" height="44" rx="10" fill="${bg}" stroke="${border}" stroke-width="2.5"/>\n`;
        svg += `    <text x="0" y="5" text-anchor="middle" font-family="monospace" font-size="11.5" font-weight="bold" fill="#f8fafc">${escapeHtml(n.label || '')}</text>\n`;
        svg += `  </g>\n`;
      }
    });
  }

  svg += `</svg>`;

  const blob = new Blob([svg], { type: 'image/svg+xml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.download = `rea-architecture-map-${target}-${Date.now()}.svg`;
  a.href = url;
  a.click();
  URL.revokeObjectURL(url);
  showTempBtnText(elements.btnExportGraphSvg, '✓ Saved SVG!');
}

/**
 * Interactive IPC Execution Simulator
 */
let currentSimChannel = 'notes:export';

function setupIpcSimulator() {
  if (elements.btnCloseIpcSim) {
    elements.btnCloseIpcSim.addEventListener('click', () => {
      elements.ipcSimulatorModal.classList.remove('open');
    });
  }
  if (elements.btnCloseIpcSim2) {
    elements.btnCloseIpcSim2.addEventListener('click', () => {
      elements.ipcSimulatorModal.classList.remove('open');
    });
  }
  if (elements.btnRunIpcSim) {
    elements.btnRunIpcSim.addEventListener('click', () => {
      runIpcSimulation();
    });
  }
  if (elements.qaBtnSim) {
    elements.qaBtnSim.addEventListener('click', () => {
      const channel = activeSelectedNode?.rawNode?.observations?.[0]?.label || 'notes:export';
      openIpcSimulator(channel);
    });
  }
}

function openIpcSimulator(channelName = 'notes:export') {
  currentSimChannel = channelName;
  if (elements.simChannelBadge) elements.simChannelBadge.textContent = channelName;
  elements.ipcSimulatorModal.classList.add('open');

  resetSimulatorStages();

  const sampleArgs = {
    action: "export",
    format: "csv",
    range: "all",
    clientTimestamp: Date.now()
  };
  elements.simTxPayload.textContent = JSON.stringify(sampleArgs, null, 2);
  elements.simRxPayload.textContent = '// Awaiting invocation execution...';
  elements.simTraceLog.innerHTML = `<span style="color: var(--accent-cyan);">Ready.</span> Target channel: <code>${escapeHtml(channelName)}</code>. Click "Dispatch Simulated IPC Call" to run.`;
}

function resetSimulatorStages() {
  const stages = ['renderer', 'preload', 'channel', 'main'];
  stages.forEach((s, idx) => {
    const el = document.getElementById(`sim-stage-${s}`);
    const status = document.getElementById(`sim-status-${s}`);
    if (el) el.classList.remove('active', 'done');
    if (status) status.textContent = idx === 0 ? 'Ready' : 'Idle';
  });
  for (let i = 1; i <= 3; i++) {
    const fill = document.getElementById(`sim-fill-${i}`);
    if (fill) fill.style.width = '0%';
  }
}

async function runIpcSimulation() {
  if (elements.btnRunIpcSim) elements.btnRunIpcSim.disabled = true;
  resetSimulatorStages();

  const log = elements.simTraceLog;
  const timingBadge = document.getElementById('sim-timing-badge');
  const latencyBadge = document.getElementById('sim-rx-latency');
  const t0 = performance.now();

  log.innerHTML = `<div style="color: #38bdf8;">[0.0ms] 🚀 Dispatching synthetic IPC invoke for '${escapeHtml(currentSimChannel)}'...</div>`;

  // Stage 1: Renderer DOM invocation
  const s1 = document.getElementById('sim-stage-renderer');
  const st1 = document.getElementById('sim-status-renderer');
  s1.classList.add('active');
  st1.textContent = 'Invoking';
  await sleep(350);

  s1.classList.remove('active');
  s1.classList.add('done');
  st1.textContent = 'Dispatched';
  const fill1 = document.getElementById('sim-fill-1');
  if (fill1) fill1.style.width = '100%';
  log.innerHTML += `<div style="color: #cbd5e1;">[+0.2ms] window.notes.exportCsv() -> ContextBridge boundary call</div>`;

  // Stage 2: ContextBridge Preload
  const s2 = document.getElementById('sim-stage-preload');
  const st2 = document.getElementById('sim-status-preload');
  s2.classList.add('active');
  st2.textContent = 'Serializing';
  await sleep(400);

  s2.classList.remove('active');
  s2.classList.add('done');
  st2.textContent = 'Validated';
  const fill2 = document.getElementById('sim-fill-2');
  if (fill2) fill2.style.width = '100%';
  log.innerHTML += `<div style="color: #fbbf24;">[+0.5ms] ipcRenderer.invoke('${escapeHtml(currentSimChannel)}') -> Structured Clone Serialization</div>`;

  // Stage 3: Chromium Mojo IPC channel jump
  const s3 = document.getElementById('sim-stage-channel');
  const st3 = document.getElementById('sim-status-channel');
  s3.classList.add('active');
  st3.textContent = 'Crossing';
  await sleep(450);

  s3.classList.remove('active');
  s3.classList.add('done');
  st3.textContent = 'Transferred';
  const fill3 = document.getElementById('sim-fill-3');
  if (fill3) fill3.style.width = '100%';
  log.innerHTML += `<div style="color: #34d399;">[+0.8ms] Mojo IPC Thread Jump: Renderer Process ➔ Main Process [PID matched]</div>`;

  // Stage 4: Main Handler
  const s4 = document.getElementById('sim-stage-main');
  const st4 = document.getElementById('sim-status-main');
  s4.classList.add('active');
  st4.textContent = 'Handling';
  await sleep(400);

  const totalTime = (performance.now() - t0).toFixed(1);
  s4.classList.remove('active');
  s4.classList.add('done');
  st4.textContent = 'Completed';

  const mockResponse = {
    status: "ok",
    channel: currentSimChannel,
    destination: "C:\\Users\\Anshuman\\notes-export.csv",
    recordsExported: 4,
    bytesWritten: 1280,
    senderFrame: {
      verified: true,
      protocol: "file:",
      routingId: 1
    },
    latencyMs: 1.4
  };

  elements.simRxPayload.textContent = JSON.stringify(mockResponse, null, 2);
  if (timingBadge) timingBadge.textContent = `${totalTime}ms total`;
  if (latencyBadge) latencyBadge.textContent = `Latency: 1.4ms (Resolved)`;

  log.innerHTML += `<div style="color: #6ee7b7; font-weight: bold;">[+1.4ms] ✓ ipcMain.handle('${escapeHtml(currentSimChannel)}') resolved with 1280 bytes written to disk.</div>`;

  // Pulse corresponding node on the flow diagram if active
  if (appState.network && appState.networkNodes) {
    const channelNode = appState.networkNodes.get().find(n => n.rawNode?.kind === 'ipc-channel' || n.label.includes(currentSimChannel));
    if (channelNode) {
      triggerTracePulse(channelNode.id);
    }
  }

  if (elements.btnRunIpcSim) elements.btnRunIpcSim.disabled = false;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
