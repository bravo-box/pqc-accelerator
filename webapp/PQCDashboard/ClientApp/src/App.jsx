import React, { useState, useEffect, useCallback } from 'react';
import Dashboard from './components/Dashboard';
import './App.css';

export default function App() {
  const [fleet, setFleet]       = useState(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [hours, setHours]       = useState(24);
  const [platformFilter, setPlatformFilter] = useState('all');
  const [lastRefresh, setLast]  = useState(null);

  const fetchFleet = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(`/api/compliance/fleet?hours=${hours}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setFleet(data);
      setLast(new Date());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [hours]);

  useEffect(() => {
    fetchFleet();
    const id = setInterval(fetchFleet, 5 * 60 * 1000); // auto-refresh every 5 min
    return () => clearInterval(id);
  }, [fetchFleet]);

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-left">
          <span className="shield">🔐</span>
          <div>
            <h1>PQC Compliance Dashboard</h1>
            <p>Post-Quantum Cryptography Readiness — Arc Fleet</p>
          </div>
        </div>
        <div className="header-right">
          <select value={hours} onChange={e => setHours(+e.target.value)} className="time-select">
            <option value={1}>Last 1 hour</option>
            <option value={6}>Last 6 hours</option>
            <option value={24}>Last 24 hours</option>
            <option value={168}>Last 7 days</option>
          </select>
          <select
            value={platformFilter}
            onChange={e => setPlatformFilter(e.target.value)}
            className="time-select"
            aria-label="Platform filter"
          >
            <option value="all">All machines</option>
            <option value="windows">Windows only</option>
            <option value="linux">Linux only</option>
          </select>
          <button onClick={fetchFleet} className="refresh-btn" disabled={loading}>
            {loading ? '⟳ Refreshing…' : '⟳ Refresh'}
          </button>
          {lastRefresh && (
            <span className="last-refresh">
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
        </div>
      </header>

      <main className="app-main">
        {error   && <div className="error-banner">⚠ {error}</div>}
        {loading && !fleet && <div className="loading">Loading compliance data…</div>}
        {fleet   && <Dashboard fleet={fleet} platformFilter={platformFilter} />}
      </main>
    </div>
  );
}
