import { useState, useCallback, useRef, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import useWebSocket from './hooks/useWebSocket';
import Dashboard from './components/Dashboard';
import ModelAnalysis from './components/ModelAnalysis';
import FileUploadPanel from './components/FileUploadPanel';
import Login from './components/Login';

/**
 * App — Root Component / Navigation Shell
 *
 * Tabs: Dashboard | File Scanner | Model Analysis
 * Simulation Start/Stop controls live in the header.
 */

// Attack types and source IPs for realistic demo traffic
const ATTACK_TYPES = ['ddos', 'dos', 'scan', 'botnet', 'theft', 'anomaly'];
const SOURCE_IPS = ['10.0.0.42', '172.16.8.7', '203.0.113.55', '198.51.100.12', '45.33.32.156'];
const DEST_IPS = ['192.168.1.1', '192.168.1.10', '192.168.1.50', '10.0.0.1'];

function IdsApp({ setIsAuthenticated }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [simRunning, setSimRunning] = useState(true); // Backend auto-starts capture
  const [simLoading, setSimLoading] = useState(false);
  const [esp32Status, setEsp32Status] = useState({});

  // Ref to hold the injection interval so we can clear it on stop
  const injectionRef = useRef(null);

  // Initialize the single WebSocket connection at the application root
  const wsData = useWebSocket();
  const { isConnected, stats } = wsData;

  // Auto-detect API base — works locally, with localtunnel, or any domain
  // On Vite dev server, use empty string so requests go through the Vite proxy (avoids CORS)
  const API_BASE = window.location.port === '5173'
    ? ''  // Vite dev: use proxy defined in vite.config.js
    : `${window.location.protocol}//${window.location.host}`; // Production: same origin

  const attackRate = stats.total > 0
    ? ((stats.attacks / stats.total) * 100).toFixed(1)
    : '0.0';

  // ── Poll ESP32 device status every 3 seconds ───────────────────────────
  useEffect(() => {
    const poll = () => {
      fetch(`${API_BASE}/api/esp32/status`)
        .then(r => r.json())
        .then(data => setEsp32Status(data))
        .catch(() => {}); // silent on failure
    };
    poll(); // initial fetch
    const timer = setInterval(poll, 3000);
    return () => clearInterval(timer);
  }, [API_BASE]);

  // Fire a single random attack injection at the backend
  const injectRandomAttack = useCallback(() => {
    const attack = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];
    const src = SOURCE_IPS[Math.floor(Math.random() * SOURCE_IPS.length)];
    const dst = DEST_IPS[Math.floor(Math.random() * DEST_IPS.length)];
    fetch(`${API_BASE}/api/inject-attack?attack_type=${attack}&source_ip=${src}&dest_ip=${dst}`, {
      method: 'POST',
    }).catch(() => { }); // silent — dashboard shows errors via WS disconnect
  }, [API_BASE]);

  // ── Capture control handlers ────────────────────────────────────────────
  const toggleSimulation = useCallback(async () => {
    setSimLoading(true);

    if (simRunning) {
      // ── STOP ─────────────────────────────────────────────────────────
      if (injectionRef.current) {
        clearInterval(injectionRef.current);
        injectionRef.current = null;
      }
      try {
        await fetch(`${API_BASE}/api/capture/stop`, { method: 'POST' });
      } catch (_) { }
      setSimRunning(false);
    } else {
      // ── START ────────────────────────────────────────────────────────
      try {
        await fetch(`${API_BASE}/api/capture/start?interface=5`, { method: 'POST' });
      } catch (_) { }
      setSimRunning(true);
    }

    setSimLoading(false);
  }, [simRunning, API_BASE]);

  return (
    <div className="min-h-screen bg-soc-bg text-soc-text font-sans">
      {/* CRT scan-line overlay for SOC aesthetic */}
      <div className="scan-overlay" aria-hidden="true" />

      {/* ── Top Header ────────────────────────────────────────────────── */}
      <header className="relative border-b border-soc-border bg-soc-surface/80 backdrop-blur-md sticky top-0 z-50">
        {/* Top accent line */}
        <div className="h-0.5 bg-gradient-to-r from-transparent via-soc-cyan to-transparent opacity-60" />

        <div className="max-w-screen-2xl mx-auto px-6 py-3 flex items-center justify-between gap-4">
          {/* Brand */}
          <div className="flex items-center gap-4 flex-shrink-0">
            {/* IDS Logo SVG */}
            <div className="relative w-10 h-10">
              <svg viewBox="0 0 40 40" className="w-full h-full">
                <polygon points="20,3 37,13 37,27 20,37 3,27 3,13" fill="none" stroke="#0284c7" strokeWidth="1.5" opacity="0.7" />
                <polygon points="20,8 32,15 32,25 20,32 8,25 8,15" fill="none" stroke="#0284c7" strokeWidth="1" opacity="0.4" />
                <text x="20" y="23" textAnchor="middle" fill="#0284c7" fontSize="10" fontWeight="bold" fontFamily="JetBrains Mono">IDS</text>
              </svg>
              {/* Animated pulse ring */}
              <div className={`absolute -inset-1 rounded-full border opacity-30 ${isConnected ? 'border-soc-cyan animate-pulse-cyan' : 'border-soc-red'}`} />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-wider text-soc-text">
                AI<span className="text-soc-cyan">·</span>IDS DASHBOARD
              </h1>
              <p className="text-xs text-soc-muted font-mono tracking-widest">
                MULTI-LAYER INTRUSION DETECTION SYSTEM
              </p>
            </div>
          </div>

          {/* Status indicators */}
          <div className="hidden md:flex items-center gap-5 flex-shrink-0">
            {/* Connection status */}
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-soc-green animate-pulse' : 'bg-soc-red'}`} />
              <span className={`text-xs font-mono font-semibold tracking-wider ${isConnected ? 'text-soc-green' : 'text-soc-red'}`}>
                {isConnected ? 'LIVE FEED' : 'DISCONNECTED'}
              </span>
            </div>

            {/* Packet counter */}
            <div className="text-center">
              <div className="text-soc-cyan font-mono font-bold text-base leading-none">
                {stats.total.toLocaleString()}
              </div>
              <div className="text-xs text-soc-muted tracking-widest mt-0.5">PACKETS</div>
            </div>

            {/* Attack rate */}
            <div className="text-center">
              <div className={`font-mono font-bold text-base leading-none ${parseFloat(attackRate) > 30 ? 'text-soc-red' :
                  parseFloat(attackRate) > 15 ? 'text-soc-amber' : 'text-soc-green'
                }`}>
                {attackRate}%
              </div>
              <div className="text-xs text-soc-muted tracking-widest mt-0.5">ATTACK RATE</div>
            </div>

            {/* Dataset badge */}
            <div className="hidden xl:block px-3 py-1.5 border border-soc-cyan/30 bg-soc-cyan/5 rounded-lg">
              <span className="text-xs text-soc-cyan font-mono tracking-wider">Custom ESP32 Model (Binary)</span>
            </div>
          </div>

          {/* ── Simulation Control Buttons ─────────────────────────────── */}
          <div className="flex items-center gap-3 flex-shrink-0">
            {/* Start / Stop toggle button */}
            <button
              id="btn-sim-toggle"
              onClick={toggleSimulation}
              disabled={simLoading}
              className={`
                relative flex items-center gap-2 px-4 py-2 rounded-lg font-mono text-sm font-semibold
                border transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-1
                focus:ring-offset-soc-bg disabled:opacity-60 disabled:cursor-wait
                ${simRunning
                  ? 'border-soc-red/60 bg-soc-red/10 text-soc-red hover:bg-soc-red/20 focus:ring-soc-red/40'
                  : 'border-soc-green/60 bg-soc-green/10 text-soc-green hover:bg-soc-green/20 focus:ring-soc-green/40'
                }
              `}
              title={simRunning ? 'Stop live simulation' : 'Start live simulation'}
            >
              {simLoading ? (
                /* Spinner while API call is in-flight */
                <span className="w-3.5 h-3.5 rounded-full border-2 border-current border-t-transparent animate-spin" />
              ) : simRunning ? (
                /* Stop icon — square */
                <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor">
                  <rect x="2" y="2" width="10" height="10" rx="1.5" />
                </svg>
              ) : (
                /* Play icon — triangle */
                <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor">
                  <path d="M3 2.5l9 4.5-9 4.5V2.5z" />
                </svg>
              )}
              {simRunning ? 'Stop Capture' : 'Start Capture'}
            </button>

            {/* Simulation status pill */}
            <div className={`
              hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-mono
              ${simRunning
                ? 'border-soc-green/30 bg-soc-green/5 text-soc-green'
                : 'border-soc-red/30 bg-soc-red/5 text-soc-red'}
            `}>
              <span className={`w-1.5 h-1.5 rounded-full ${simRunning ? 'bg-soc-green animate-pulse' : 'bg-soc-red'}`} />
              {simRunning ? 'CAPTURING' : 'STOPPED'}
            </div>
          </div>

          {/* Navigation tabs */}
          <nav className="flex items-center gap-2 flex-shrink-0">
            <button
              id="nav-dashboard"
              onClick={() => setActiveTab('dashboard')}
              className={`nav-tab ${activeTab === 'dashboard' ? 'nav-tab-active' : 'nav-tab-inactive'}`}
            >
              Dashboard
            </button>
            <button
              id="nav-file-scanner"
              onClick={() => setActiveTab('file-scanner')}
              className={`nav-tab ${activeTab === 'file-scanner' ? 'nav-tab-active' : 'nav-tab-inactive'}`}
            >
              File Scanner
            </button>
            <button
              id="nav-model-analysis"
              onClick={() => setActiveTab('model-analysis')}
              className={`nav-tab ${activeTab === 'model-analysis' ? 'nav-tab-active' : 'nav-tab-inactive'}`}
            >
              Model Analysis
            </button>
            <button
              onClick={() => {
                localStorage.removeItem('ids_token');
                setIsAuthenticated(false);
              }}
              className="px-3 py-1.5 rounded-lg border border-soc-red/30 text-soc-red text-sm font-mono hover:bg-soc-red/10 ml-4"
            >
              Logout
            </button>
          </nav>
        </div>
      </header>

      {/* ── Main Content ─────────────────────────────────────────────── */}
      <main className="max-w-screen-2xl mx-auto px-4 py-4">
        {activeTab === 'dashboard' && <Dashboard {...wsData} esp32Status={esp32Status} />}
        {activeTab === 'file-scanner' && <FileUploadPanel />}
        {activeTab === 'model-analysis' && <ModelAnalysis stats={stats} />}
      </main>

      {/* ── Footer ───────────────────────────────────────────────────── */}
      <footer className="border-t border-soc-border py-2 px-6 flex items-center justify-between text-xs text-soc-muted font-mono">
        <span>FastAPI WebSocket :8000 → TShark/Scapy → XGBoost ESP32 Model → React</span>
        <span>Hardware-in-the-Loop AI Edge Prototype · Binary Classification</span>
        <span>Secure Dashboard</span>
      </footer>
    </div>
  );
}

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('ids_token'));

  return (
    <Router>
      <Routes>
        <Route 
          path="/login" 
          element={<Login setIsAuthenticated={setIsAuthenticated} />} 
        />
        <Route 
          path="/*" 
          element={
            isAuthenticated ? (
              <IdsApp setIsAuthenticated={setIsAuthenticated} />
            ) : (
              <Navigate to="/login" replace />
            )
          } 
        />
      </Routes>
    </Router>
  );
}
