import React, { useEffect, useMemo, useState } from 'react'
import {
  Chart,
  LineController,
  LineElement,
  PointElement,
  LinearScale,
  CategoryScale,
  BarController,
  BarElement,
  DoughnutController,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js'

Chart.register(
  LineController,
  LineElement,
  PointElement,
  LinearScale,
  CategoryScale,
  BarController,
  BarElement,
  DoughnutController,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
)

const API = 'http://localhost:8000'

function SeverityPill({ value }) {
  return <span className={`pill ${String(value || '').toLowerCase()}`}>{value}</span>
}

function ModePill({ value }) {
  return <span className={`mode-pill ${value}`}>{value}</span>
}

function KpiCard({ label, value, note }) {
  return (
    <div className="card kpi-card">
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-note">{note}</div>
    </div>
  )
}

function ChartPanel({ title, canvasId, rightText }) {
  return (
    <div className="card panel-card">
      <div className="panel-head">
        <h3>{title}</h3>
        {rightText ? <span className="muted">{rightText}</span> : null}
      </div>
      <canvas id={canvasId}></canvas>
    </div>
  )
}

function ReplayModal({ sourceIp, replay, onClose }) {
  if (!sourceIp) return null
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-lg" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <h3>Attacker Replay</h3>
            <p>{sourceIp}</p>
          </div>
          <button className="ghost-btn" onClick={onClose}>Close</button>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Mode</th>
                <th>Method</th>
                <th>Path</th>
                <th>Decoy</th>
                <th>Severity</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {replay.map((row, idx) => (
                <tr key={idx}>
                  <td>{new Date(row.ts).toLocaleString()}</td>
                  <td><ModePill value={row.mode} /></td>
                  <td>{row.method}</td>
                  <td className="mono">{row.path}</td>
                  <td>{row.decoy_name}</td>
                  <td><SeverityPill value={row.severity} /></td>
                  <td>{row.risk_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default function App() {
  const [stats, setStats] = useState(null)
  const [incidents, setIncidents] = useState([])
  const [timeline, setTimeline] = useState([])
  const [sources, setSources] = useState([])
  const [hotDecoys, setHotDecoys] = useState([])
  const [countries, setCountries] = useState([])
  const [campaigns, setCampaigns] = useState([])
  const [geoPoints, setGeoPoints] = useState([])
  const [chain, setChain] = useState(null)
  const [loading, setLoading] = useState(false)
  const [replaySourceIp, setReplaySourceIp] = useState(null)
  const [replayRows, setReplayRows] = useState([])

  const refreshAll = async () => {
    setLoading(true)
    try {
      const [
        statsRes,
        incidentsRes,
        timelineRes,
        chainRes,
        sourcesRes,
        hotDecoysRes,
        countriesRes,
        campaignsRes,
        geoPointsRes,
      ] = await Promise.all([
        fetch(`${API}/stats`).then(r => r.json()),
        fetch(`${API}/incidents?limit=20`).then(r => r.json()),
        fetch(`${API}/timeline?limit=50`).then(r => r.json()),
        fetch(`${API}/audit/verify`).then(r => r.json()),
        fetch(`${API}/sources/top?limit=8`).then(r => r.json()),
        fetch(`${API}/decoys/hot?limit=8`).then(r => r.json()),
        fetch(`${API}/geo/countries?limit=10`).then(r => r.json()),
        fetch(`${API}/campaigns?limit=10`).then(r => r.json()),
        fetch(`${API}/geo/points?limit=100`).then(r => r.json()),
      ])

      setStats(statsRes)
      setIncidents(incidentsRes.incidents || [])
      setTimeline(timelineRes.timeline || [])
      setChain(chainRes)
      setSources(sourcesRes.sources || [])
      setHotDecoys(hotDecoysRes.decoys || [])
      setCountries(countriesRes.countries || [])
      setCampaigns(campaignsRes.campaigns || [])
      setGeoPoints(geoPointsRes.points || [])
    } finally {
      setLoading(false)
    }
  }

  const generateDemo = async () => {
    setLoading(true)
    await fetch(`${API}/demo/generate?count=30`, { method: 'POST' })
    await refreshAll()
  }

  const triggerLiveDecoys = async () => {
    setLoading(true)
    try {
      await fetch(`${API}/admin`)
      await fetch(`${API}/.env`)
      await fetch(`${API}/latest/meta-data`)
      await fetch(`${API}/jenkins/script`)
    } finally {
      await refreshAll()
    }
  }

  const openReplay = async (sourceIp) => {
    const data = await fetch(`${API}/replay/${sourceIp}`).then(r => r.json())
    setReplaySourceIp(sourceIp)
    setReplayRows(data.replay || [])
  }

  useEffect(() => {
    refreshAll()
    const t = setInterval(refreshAll, 15000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    const riskCanvas = document.getElementById('riskChart')
    const sourceCanvas = document.getElementById('sourceChart')
    const modeCanvas = document.getElementById('modeChart')
    const countryCanvas = document.getElementById('countryChart')

    if (!riskCanvas || !sourceCanvas || !modeCanvas || !countryCanvas) return

    Chart.getChart(riskCanvas)?.destroy()
    Chart.getChart(sourceCanvas)?.destroy()
    Chart.getChart(modeCanvas)?.destroy()
    Chart.getChart(countryCanvas)?.destroy()

    const reversed = [...timeline].reverse()
    const labels = reversed.map(item => new Date(item.ts).toLocaleTimeString())
    const risks = reversed.map(item => item.risk_score)

    new Chart(riskCanvas, {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Risk Score',
          data: risks,
          borderColor: '#4de2ff',
          backgroundColor: 'rgba(77,226,255,0.14)',
          fill: true,
          tension: 0.35,
          pointRadius: 3,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#dfe9ff' } } },
        scales: {
          x: { ticks: { color: '#8ea4c8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
          y: { ticks: { color: '#8ea4c8' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true, max: 100 }
        }
      }
    })

    new Chart(sourceCanvas, {
      type: 'bar',
      data: {
        labels: sources.map(s => s.source_ip),
        datasets: [{
          label: 'Hits',
          data: sources.map(s => s.hits),
          backgroundColor: ['#4de2ff', '#9c89ff', '#57f287', '#ffd166', '#ff5f7a', '#6dd3ff', '#b89cff', '#75f0aa'],
          borderRadius: 10,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#dfe9ff' } } },
        scales: {
          x: { ticks: { color: '#8ea4c8' }, grid: { display: false } },
          y: { ticks: { color: '#8ea4c8' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
        }
      }
    })

    new Chart(modeCanvas, {
      type: 'doughnut',
      data: {
        labels: ['Live', 'Demo'],
        datasets: [{
          data: [stats?.live_events || 0, stats?.demo_events || 0],
          backgroundColor: ['#4de2ff', '#9c89ff'],
          borderColor: ['#06111d', '#06111d'],
          borderWidth: 3,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#dfe9ff' } } }
      }
    })

    new Chart(countryCanvas, {
      type: 'bar',
      data: {
        labels: countries.map(c => c.geo_country),
        datasets: [{
          label: 'Country Hits',
          data: countries.map(c => c.hits),
          backgroundColor: '#57f287',
          borderRadius: 10,
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#dfe9ff' } } },
        scales: {
          x: { ticks: { color: '#8ea4c8' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true },
          y: { ticks: { color: '#8ea4c8' }, grid: { display: false } }
        }
      }
    })
  }, [timeline, sources, stats, countries])

  const statusText = useMemo(() => {
    if (!chain) return 'Verifying audit ledger...'
    return chain.valid ? `Audit chain valid across ${chain.blocks} blocks` : `Audit chain broken at block ${chain.broken_at}`
  }, [chain])

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <div className="eyebrow">Cyber Deception Platform</div>
          <h1>Sentinel Shadow v3</h1>
          <p>Live decoys, GeoIP enrichment, NVD intelligence, webhook alerts, and attacker campaign analysis.</p>
        </div>
        <div className="actions">
          <button onClick={generateDemo}>{loading ? 'Working...' : 'Generate Demo Traffic'}</button>
          <button className="secondary" onClick={triggerLiveDecoys}>Trigger Live Decoys</button>
          <button className="secondary" onClick={refreshAll}>Refresh</button>
          <a className="secondary link-btn" href={`${API}/metrics`} target="_blank" rel="noreferrer">Open Metrics</a>
        </div>
      </header>

      <section className="kpi-grid six">
        <KpiCard label="Total Events" value={stats?.total_events ?? 0} note="All captured honeypot interactions" />
        <KpiCard label="Critical Alerts" value={stats?.critical_alerts ?? 0} note="Highest-confidence detections" />
        <KpiCard label="Average Risk" value={stats?.avg_risk_score ?? 0} note="Combined anomaly and context score" />
        <KpiCard label="Live Events" value={stats?.live_events ?? 0} note="Captured from decoy routes" />
        <KpiCard label="Demo Events" value={stats?.demo_events ?? 0} note="Synthetic demo traffic" />
        <KpiCard label="Chain Integrity" value={chain?.valid ? 'VALID' : 'CHECKING'} note={statusText} />
      </section>

      <section className="main-grid">
        <ChartPanel title="Threat Escalation Timeline" canvasId="riskChart" rightText="Risk score over time" />
        <ChartPanel title="Live vs Demo Split" canvasId="modeChart" rightText="Traffic mode distribution" />
        <ChartPanel title="Top Source IPs" canvasId="sourceChart" rightText="Most active origins" />
        <ChartPanel title="Country Heat List" canvasId="countryChart" rightText="Source concentration by country" />

        <div className="card panel-card full-span">
          <div className="panel-head">
            <h3>Attacker Campaigns</h3>
            <span className="muted">Grouped by source IP with replay support</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Country</th>
                  <th>Hits</th>
                  <th>Peak Risk</th>
                  <th>First Seen</th>
                  <th>Last Seen</th>
                  <th>Decoys</th>
                  <th>Replay</th>
                </tr>
              </thead>
              <tbody>
                {campaigns.map((campaign, idx) => (
                  <tr key={idx}>
                    <td className="mono">{campaign.source_ip}</td>
                    <td>{campaign.geo_country}</td>
                    <td>{campaign.hits}</td>
                    <td>{campaign.peak_risk}</td>
                    <td>{new Date(campaign.first_seen).toLocaleString()}</td>
                    <td>{new Date(campaign.last_seen).toLocaleString()}</td>
                    <td>{campaign.decoys}</td>
                    <td><button className="secondary small-btn" onClick={() => openReplay(campaign.source_ip)}>Open</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card panel-card">
          <div className="panel-head">
            <h3>Hot Decoys</h3>
            <span className="muted">Most targeted bait assets</span>
          </div>
          <div className="stack-list">
            {hotDecoys.map(item => (
              <div className="stack-item" key={`${item.decoy_name}-${item.decoy_type}`}>
                <div>
                  <strong>{item.decoy_name}</strong>
                  <div className="muted">{item.decoy_type}</div>
                </div>
                <div className="stack-right">
                  <div className="score-badge">{item.hits} hits</div>
                  <div className="muted small">peak risk {item.peak_risk}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="card panel-card">
          <div className="panel-head">
            <h3>Geo Points</h3>
            <span className="muted">Country / city / coordinates</span>
          </div>
          <div className="table-wrap compact-table">
            <table>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Country</th>
                  <th>Lat</th>
                  <th>Lon</th>
                </tr>
              </thead>
              <tbody>
                {geoPoints.slice(0, 10).map((p, idx) => (
                  <tr key={idx}>
                    <td className="mono">{p.source_ip}</td>
                    <td>{p.geo_country}</td>
                    <td>{p.latitude ?? '--'}</td>
                    <td>{p.longitude ?? '--'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card table-card full-span">
          <div className="panel-head">
            <h3>Incident Feed</h3>
            <span className="muted">Latest telemetry across live and demo modes</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Mode</th>
                  <th>Source IP</th>
                  <th>Country</th>
                  <th>Path</th>
                  <th>Decoy</th>
                  <th>Severity</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map(incident => (
                  <tr key={incident.id}>
                    <td>{new Date(incident.ts).toLocaleTimeString()}</td>
                    <td><ModePill value={incident.mode} /></td>
                    <td className="mono">{incident.source_ip}</td>
                    <td>{incident.geo_country || 'Unknown'}</td>
                    <td className="mono">{incident.path}</td>
                    <td>{incident.decoy_name}</td>
                    <td><SeverityPill value={incident.severity} /></td>
                    <td>{incident.risk_score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <ReplayModal sourceIp={replaySourceIp} replay={replayRows} onClose={() => setReplaySourceIp(null)} />
    </div>
  )
}