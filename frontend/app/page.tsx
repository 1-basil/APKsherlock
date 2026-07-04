'use client'

import type React from 'react'
import { useState, useRef, useCallback } from 'react'

/* ═══════════════════════════════════════════════════════════════
   TYPES
   ═══════════════════════════════════════════════════════════════ */
interface ModuleResult {
  name: string
  status: 'pending' | 'running' | 'passed' | 'failed' | 'skipped'
  data?: any
  error?: string
}

interface AnalysisResults {
  file_metadata?: any
  apk_metadata?: any
  permissions?: any
  certificate?: any
  iocs?: any
  manifest?: any
  code_analysis?: any
  packer_analysis?: any
  threat_assessment?: any
  file_tree?: any[]
  native_libs?: string[]
  dex_files?: string[]
  nested_analysis?: any
  dynamic_analysis?: any
  ai_analysis?: any
}

type AppView = 'upload' | 'analyzing' | 'results'

/* ═══════════════════════════════════════════════════════════════
   MODULE PIPELINE (Matches test_analyzer.py)
   ═══════════════════════════════════════════════════════════════ */
const MODULES = [
  'File Metadata & Hashes',
  'APK Extraction & File Tree',
  'Androguard Deep Analysis',
  'Permission Risk Analysis',
  'Certificate & Identity',
  'IOC Extraction',
  'Manifest Deep Analysis',
  'Dropper & Nested APK Analysis',
  'Packer & Obfuscation Detection',
  'Code Risk Analysis',
  'VirusTotal Check',
  'Dynamic PCAP Capture',
  'Threat Scoring',
  'AI Threat Analysis',
]

function generateMockResults(fileName: string, fileSize: number): AnalysisResults {
  const hash = Array.from({ length: 64 }, () =>
    '0123456789abcdef'[Math.floor(Math.random() * 16)]
  ).join('')

  return {
    file_metadata: {
      filename: fileName,
      size_bytes: fileSize,
      size_mb: (fileSize / 1024 / 1024).toFixed(2),
      hashes: {
        md5: hash.slice(0, 32),
        sha1: hash.slice(0, 40),
        sha256: hash,
      },
      analyzed_at: new Date().toISOString(),
    },
    apk_metadata: {
      package_name: 'com.example.' + fileName.replace('.apk', '').toLowerCase().replace(/[^a-z]/g, ''),
      app_name: fileName.replace('.apk', ''),
      version_name: '1.0.0',
      version_code: '1',
      min_sdk: '21',
      target_sdk: '33',
      is_valid_apk: true,
      permissions: [
        'android.permission.INTERNET',
        'android.permission.ACCESS_NETWORK_STATE',
        'android.permission.READ_PHONE_STATE',
        'android.permission.SEND_SMS',
        'android.permission.READ_CONTACTS',
        'android.permission.CAMERA',
        'android.permission.RECORD_AUDIO',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.WRITE_EXTERNAL_STORAGE',
        'android.permission.RECEIVE_BOOT_COMPLETED',
        'android.permission.SYSTEM_ALERT_WINDOW',
      ],
      activities: [
        'com.example.app.MainActivity',
        'com.example.app.SplashActivity',
        'com.example.app.SettingsActivity',
      ],
      services: ['com.example.app.BackgroundService'],
      receivers: ['com.example.app.BootReceiver'],
      providers: [],
      main_activity: 'com.example.app.MainActivity',
    },
    permissions: {
      total_permissions: 12,
      risk_grade: 'HIGH',
      risk_percentage: 72,
      categorized: {
        CRITICAL: ['android.permission.SEND_SMS', 'android.permission.SYSTEM_ALERT_WINDOW'],
        DANGEROUS: [
          'android.permission.READ_CONTACTS',
          'android.permission.CAMERA',
          'android.permission.RECORD_AUDIO',
          'android.permission.ACCESS_FINE_LOCATION',
        ],
        NORMAL: [
          'android.permission.INTERNET',
          'android.permission.ACCESS_NETWORK_STATE',
          'android.permission.READ_PHONE_STATE',
          'android.permission.READ_EXTERNAL_STORAGE',
          'android.permission.WRITE_EXTERNAL_STORAGE',
          'android.permission.RECEIVE_BOOT_COMPLETED',
        ],
      },
      dangerous_combinations: [
        {
          name: 'SMS Fraud Kit',
          severity: 'CRITICAL',
          forensic_significance: 'SEND_SMS + READ_PHONE_STATE can be used for premium-rate SMS fraud.',
          match_percentage: 100,
        },
        {
          name: 'Stalkerware Suite',
          severity: 'HIGH',
          forensic_significance: 'CAMERA + RECORD_AUDIO + FINE_LOCATION enables covert surveillance.',
          match_percentage: 85,
        },
      ],
    },
    certificate: {
      certificates: [
        {
          subject: {
            common_name: 'Android Debug',
            organization: 'Unknown',
            country: 'US',
            email: 'unknown@debug.local',
          },
          validity: {
            not_before: '2024-01-01T00:00:00Z',
            not_after: '2054-01-01T00:00:00Z',
          },
          hashes: { sha256: hash.slice(0, 64) },
        },
      ],
      signing_scheme: 'v1 (JAR)',
      is_self_signed: true,
      is_debug_signed: true,
      attribution_clues: {
        developer_name: 'Android Debug',
        organization: 'Unknown',
        country: 'US',
        investigation_notes: [
          'Debug certificate detected — app was NOT properly signed for distribution',
          'Self-signed certificate — not from a trusted CA',
          'No organization info — possible amateur or malicious developer',
        ],
      },
    },
    iocs: {
      iocs: {
        ipv4_address: [
          { value: '192.168.1.100', source: 'classes.dex', investigation_note: 'Internal network IP' },
          { value: '45.33.32.156', source: 'classes.dex', investigation_note: 'External server — investigate' },
        ],
        domain: [
          { value: 'api.malware-c2.xyz', source: 'classes2.dex', investigation_note: 'Suspected C2 domain' },
          { value: 'cdn.tracker-ads.com', source: 'classes.dex', investigation_note: 'Known ad tracker' },
        ],
        url_full: [
          { value: 'https://api.malware-c2.xyz/gate.php', source: 'classes.dex', investigation_note: 'C2 gate URL' },
        ],
        api_key_generic: [
          { value: 'AIzaSyD...redacted...Kx8', source: 'classes.dex', investigation_note: 'Google API key exposed' },
        ],
        email_address: [
          { value: 'dev@suspicious-domain.ru', source: '__strings_dump__', investigation_note: 'Russian email' },
        ],
        crypto_bitcoin: [
          { value: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', source: '__strings_dump__', investigation_note: 'Bitcoin wallet found' },
        ],
      },
      summary: {
        total_iocs: 42,
        critical_count: 8,
        has_c2_indicators: true,
        has_financial_indicators: true,
      },
    },
    manifest: {
      components: {
        activities: [
          { name: 'com.example.app.MainActivity', exported: true },
          { name: 'com.example.app.SplashActivity', exported: false },
        ],
        services: [{ name: 'com.example.app.BackgroundService', exported: true }],
        receivers: [{ name: 'com.example.app.BootReceiver', exported: true }],
        providers: [],
      },
      exported_attack_surface: {
        activities: [{ name: 'com.example.app.MainActivity' }],
        services: [{ name: 'com.example.app.BackgroundService' }],
        receivers: [{ name: 'com.example.app.BootReceiver' }],
        providers: [],
      },
      misconfigurations: [
        { type: 'ALLOW_BACKUP', severity: 'MEDIUM', description: 'App data can be backed up via ADB' },
        { type: 'DEBUGGABLE', severity: 'HIGH', description: 'Application is debuggable' },
      ],
    },
    code_analysis: {
      code_risk_score: 65,
      capabilities: [
        { capability: 'Cryptographic Operations', risk: 'MEDIUM', evidence_count: 12, description: 'Uses javax.crypto / java.security' },
        { capability: 'Runtime Execution', risk: 'CRITICAL', evidence_count: 3, description: 'Runtime.exec() or ProcessBuilder detected' },
        { capability: 'SMS Operations', risk: 'HIGH', evidence_count: 5, description: 'SmsManager / sendTextMessage usage' },
        { capability: 'Native Code Loading', risk: 'MEDIUM', evidence_count: 2, description: 'System.loadLibrary calls' },
        { capability: 'Network Communication', risk: 'LOW', evidence_count: 18, description: 'HTTP client / socket usage' },
      ],
      obfuscation: {
        is_obfuscated: true,
        obfuscation_percentage: 34,
        detected_packers: ['ProGuard'],
      },
    },
    packer_analysis: {
        is_packed: true,
        detected_packers: ['Naga Protect / Nagapt'],
        encrypted_blobs: [
            { path: 'assets/payload.blob', size_kb: 3950.4, entropy: 7.95, xor_header_hits: [{'key_hex': '0x5a', 'revealed_type': 'DEX (Standard)'}] }
        ]
    },
    nested_analysis: {
        total_hidden_payloads: 2,
        dropper_indicators: {
            classification: 'Advanced Dropper',
            dropper_confidence: 95
        },
        payloads: [
            { source_path: 'lib/arm64-v8a/libnpdcc.so', is_disguised: false, file_type: 'ELF_BINARY', size_kb: 455.7 },
            { source_path: 'assets/payload.blob', is_disguised: true, file_type: 'ENCRYPTED_ARCHIVE', size_kb: 3950.4 }
        ]
    },
    dynamic_analysis: {
        network_traffic: {
            unique_ips: ['192.168.1.5', '185.20.14.88', '45.133.1.22'],
            dns_queries: ['api.cerberus-update.ru', 'c2-server.malicious.net'],
            http_requests: [
                { request: 'POST /api/v1/bot/register HTTP/1.1', host: 'api.cerberus-update.ru' },
                { request: 'GET /payload/stage2.apk HTTP/1.1', host: '45.133.1.22' }
            ],
            summary: {
                total_packets: 4520,
                unique_ips_count: 3,
                dns_query_count: 2,
                http_request_count: 2
            }
        }
    },
    threat_assessment: {
      score: 73,
      grade: 'HIGH',
      verdict: 'SUSPICIOUS — LIKELY MALICIOUS',
      factors: [
        'High-risk permissions (72% risk score)',
        'Dangerous permission combo: SMS Fraud Kit',
        'Dangerous permission combo: Stalkerware Suite',
        'Critical code capability: Runtime Execution',
        'C2 communication indicators found',
        'Financial crime indicators (crypto wallets)',
      ],
    },
    file_tree: [
      { path: 'classes.dex', size: 2048000, type: 'dalvik_bytecode', suspicious: false },
      { path: 'classes2.dex', size: 1024000, type: 'dalvik_bytecode', suspicious: false },
      { path: 'classes3.dex', size: 512000, type: 'dalvik_bytecode', suspicious: false },
      { path: 'AndroidManifest.xml', size: 4096, type: 'xml_resource', suspicious: false },
      { path: 'resources.arsc', size: 128000, type: 'unknown', suspicious: false },
      { path: 'lib/arm64-v8a/libnative.so', size: 256000, type: 'native_library', suspicious: false },
      { path: 'assets/config.json', size: 2048, type: 'json_data', suspicious: false, flag: 'CONFIG_FILE' },
      { path: 'assets/payload.dex', size: 65536, type: 'dalvik_bytecode', suspicious: true },
    ],
    dex_files: ['classes.dex', 'classes2.dex', 'classes3.dex'],
    native_libs: ['lib/arm64-v8a/libnative.so'],
  }
}

async function runRealAnalysis(
  file: File,
  onModuleUpdate: (idx: number, status: ModuleResult['status']) => void
): Promise<AnalysisResults> {
  const formData = new FormData()
  formData.append('file', file)

  onModuleUpdate(0, 'running')

  const uploadRes = await fetch('http://localhost:8000/upload', {
    method: 'POST',
    body: formData,
  })

  if (!uploadRes.ok) throw new Error('Upload failed')
  const { task_id } = await uploadRes.json()

  onModuleUpdate(0, 'passed')
  onModuleUpdate(1, 'running')

  while (true) {
    await new Promise(r => setTimeout(r, 2000))
    const statusRes = await fetch(`http://localhost:8000/status/${task_id}`)
    const statusData = await statusRes.json()

    const currentStatus = statusData.status
    if (currentStatus === 'completed') {
      for (let i = 1; i < MODULES.length; i++) onModuleUpdate(i, 'passed')
      return statusData.result
    } else if (currentStatus === 'failed') {
      throw new Error(statusData.error || 'Analysis failed')
    } else {
      const pendingIdx = MODULES.findIndex((_m, i) => i > 0 && Math.random() > 0.7)
      if (pendingIdx > 0) onModuleUpdate(pendingIdx, 'running')
    }
  }
}

/* ═══════════════════════════════════════════════════════════════
   MAIN PAGE COMPONENT
   ═══════════════════════════════════════════════════════════════ */
export default function Home() {
  const [view, setView] = useState<AppView>('upload')
  const [file, setFile] = useState<File | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [modules, setModules] = useState<ModuleResult[]>(
    MODULES.map((name) => ({ name, status: 'pending' }))
  )
  const [results, setResults] = useState<AnalysisResults | null>(null)
  const [activeTab, setActiveTab] = useState('overview')
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  const handleFile = useCallback((f: File) => {
    if (f.name.endsWith('.apk')) setFile(f)
  }, [])

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setIsDragging(false)
      const f = e.dataTransfer.files[0]
      if (f) handleFile(f)
    },
    [handleFile]
  )

  const startAnalysis = useCallback(async () => {
    if (!file) return
    setView('analyzing')
    setModules(MODULES.map((name) => ({ name, status: 'pending' })))

    try {
      const res = await runRealAnalysis(file, (idx, status) => {
        setModules((prev) =>
          prev.map((m, i) => (i === idx ? { ...m, status } : m))
        )
      })
      setResults(res)
      setView('results')
    } catch (e) {
      alert('Analysis failed: ' + e)
      setView('upload')
    }
  }, [file])

  return (
    <div style={{ position: 'relative', zIndex: 1, minHeight: '100vh' }}>
      {/* ════ NAVBAR ════ */}
      <nav style={styles.navbar}>
        <div style={styles.navInner}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={styles.logoIcon}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <span style={styles.logoText}>ForensicDroid</span>
            <span style={styles.badge}>v1.0</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            {view === 'results' && (
              <button
                style={styles.navButton}
                onClick={() => {
                  setView('upload')
                  setFile(null)
                  setResults(null)
                  setActiveTab('overview')
                  setModules(MODULES.map((name) => ({ name, status: 'pending' })))
                }}
              >
                ← New Analysis
              </button>
            )}
            <span style={{ color: 'var(--text-muted)', fontSize: '13px' }} className="mono">
              {new Date().toLocaleDateString()}
            </span>
          </div>
        </div>
      </nav>

      {/* ════ CONTENT ════ */}
      <main style={styles.main}>
        {view === 'upload' && (
          <UploadView
            file={file}
            isDragging={isDragging}
            fileInputRef={fileInputRef}
            onFile={handleFile}
            onDrop={handleDrop}
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true) }}
            onDragLeave={() => setIsDragging(false)}
            onStart={startAnalysis}
          />
        )}
        {view === 'analyzing' && <AnalyzingView modules={modules} fileName={file?.name || ''} />}
        {view === 'results' && results && (
          <ResultsView results={results} activeTab={activeTab} onTabChange={setActiveTab} />
        )}
      </main>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   UPLOAD VIEW
   ═══════════════════════════════════════════════════════════════ */
function UploadView({
  file, isDragging, fileInputRef, onFile, onDrop, onDragOver, onDragLeave, onStart,
}: {
  file: File | null
  isDragging: boolean
  fileInputRef: React.RefObject<HTMLInputElement>
  onFile: (f: File) => void
  onDrop: (e: React.DragEvent) => void
  onDragOver: (e: React.DragEvent) => void
  onDragLeave: () => void
  onStart: () => void
}) {
  return (
    <div style={{ maxWidth: 720, margin: '0 auto', animation: 'fadeInUp 0.6s var(--ease-out)' }}>
      {/* Hero */}
      <div style={{ textAlign: 'center', marginBottom: 48 }}>
        <div style={styles.heroIconWrap}>
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <div style={styles.heroRing} />
        </div>
        <h1 style={styles.heroTitle}>APK Forensic Analysis</h1>
        <p style={styles.heroSub}>
          Upload an Android APK for comprehensive static analysis, IOC extraction,
          permission auditing, and automated threat scoring.
        </p>
      </div>

      {/* Drop zone */}
      <div
        style={{
          ...styles.dropZone,
          borderColor: isDragging ? 'var(--accent-cyan)' : file ? 'var(--accent-cyan)' : 'var(--border-light)',
          background: isDragging ? 'var(--accent-cyan-dim)' : file ? 'rgba(6,214,160,0.05)' : 'var(--bg-card)',
        }}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onClick={() => fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".apk"
          style={{ display: 'none' }}
          onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])}
        />
        {file ? (
          <>
            <div style={styles.fileIcon}>📦</div>
            <p style={{ fontSize: 18, fontWeight: 600, color: 'var(--accent-cyan)' }}>{file.name}</p>
            <p style={{ color: 'var(--text-secondary)', fontSize: 14 }}>
              {(file.size / 1024 / 1024).toFixed(2)} MB • Ready for analysis
            </p>
          </>
        ) : (
          <>
            <div style={styles.uploadIcon}>
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                <polyline points="17 8 12 3 7 8" />
                <line x1="12" y1="3" x2="12" y2="15" />
              </svg>
            </div>
            <p style={{ fontSize: 17, fontWeight: 500 }}>
              Drop APK here or <span style={{ color: 'var(--accent-cyan)', cursor: 'pointer' }}>browse</span>
            </p>
            <p style={{ color: 'var(--text-muted)', fontSize: 13, marginTop: 4 }}>
              Supports .apk files up to 500 MB
            </p>
          </>
        )}
      </div>

      {/* Analyze button */}
      {file && (
        <button style={styles.analyzeBtn} onClick={onStart}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="11" cy="11" r="8" />
            <path d="M21 21l-4.35-4.35" />
          </svg>
          Start Forensic Analysis
        </button>
      )}

      {/* Features grid */}
      <div style={styles.featureGrid}>
        {[
          { icon: '🔍', title: 'Static Analysis', desc: 'Manifest, permissions, code patterns' },
          { icon: '🎯', title: 'IOC Extraction', desc: 'IPs, domains, keys, crypto wallets' },
          { icon: '🛡️', title: 'Threat Scoring', desc: 'Automated risk grading 0–100' },
          { icon: '📋', title: 'Forensic Report', desc: 'Full JSON report with evidence' },
        ].map((f, i) => (
          <div key={i} style={styles.featureCard}>
            <span style={{ fontSize: 28 }}>{f.icon}</span>
            <h3 style={{ fontSize: 14, fontWeight: 600, marginTop: 8 }}>{f.title}</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 4 }}>{f.desc}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   ANALYZING VIEW
   ═══════════════════════════════════════════════════════════════ */
function AnalyzingView({ modules, fileName }: { modules: ModuleResult[]; fileName: string }) {
  const done = modules.filter((m) => m.status === 'passed').length
  const pct = Math.round((done / modules.length) * 100)
  const current = modules.find((m) => m.status === 'running')

  return (
    <div style={{ maxWidth: 600, margin: '0 auto', animation: 'fadeInUp 0.5s var(--ease-out)' }}>
      <div style={{ textAlign: 'center', marginBottom: 40 }}>
        <div style={styles.spinnerWrap}>
          <div style={styles.spinner} />
          <span style={{ fontSize: 28 }}>🔬</span>
        </div>
        <h2 style={{ fontSize: 22, fontWeight: 700, marginTop: 20 }}>Analyzing {fileName}</h2>
        <p style={{ color: 'var(--text-secondary)', marginTop: 8 }}>
          {current ? `Running: ${current.name}...` : 'Preparing analysis engine...'}
        </p>
      </div>

      <div style={styles.progressTrack}>
        <div style={{ ...styles.progressFill, width: `${pct}%` }} />
      </div>
      <p style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 13, marginTop: 8 }} className="mono">
        {done}/{modules.length} modules • {pct}%
      </p>

      <div style={{ marginTop: 32, display: 'flex', flexDirection: 'column', gap: 6 }}>
        {modules.map((m, i) => (
          <div
            key={i}
            style={{
              ...styles.moduleRow,
              opacity: m.status === 'pending' ? 0.4 : 1,
              background: m.status === 'running' ? 'var(--accent-cyan-dim)' : 'transparent',
              borderColor: m.status === 'running' ? 'var(--accent-cyan)' : 'var(--border-subtle)',
            }}
          >
            <span style={{ fontSize: 16, width: 24, textAlign: 'center' }}>
              {m.status === 'pending' && '○'}
              {m.status === 'running' && '◉'}
              {m.status === 'passed' && '✅'}
              {m.status === 'failed' && '❌'}
              {m.status === 'skipped' && '⏭️'}
            </span>
            <span style={{ fontSize: 14, flex: 1 }}>
              Module {i + 1}: {m.name}
            </span>
            {m.status === 'running' && (
              <span style={{ color: 'var(--accent-cyan)', fontSize: 12 }} className="mono">
                running...
              </span>
            )}
            {m.status === 'failed' && m.error && (
              <span style={{ color: 'var(--accent-red)', fontSize: 11 }} className="mono">
                {m.error}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   RESULTS VIEW  — fixed JSX structure + null guards
   ═══════════════════════════════════════════════════════════════ */
function ResultsView({
  results, activeTab, onTabChange,
}: {
  results: AnalysisResults
  activeTab: string
  onTabChange: (t: string) => void
}) {
  const threat = results.threat_assessment ?? {}
  const meta = results.file_metadata ?? {}
  const apk = results.apk_metadata ?? {}
  const factors: string[] = threat.factors ?? []

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'permissions', label: 'Permissions' },
    { id: 'iocs', label: 'Static IOCs' },
    { id: 'network', label: 'Dynamic Network' },
    { id: 'manifest', label: 'Manifest' },
    { id: 'code', label: 'Code & Packers' },
    { id: 'droppers', label: 'Payloads' },
    { id: 'certificate', label: 'Certificate' },
    { id: 'files', label: 'File Tree' },
  ]

  const gradeColors: Record<string, string> = {
    CRITICAL: 'var(--accent-red)',
    HIGH: 'var(--accent-orange)',
    MEDIUM: 'var(--accent-yellow)',
    LOW: 'var(--accent-cyan)',
    CLEAN: 'var(--accent-cyan)',
  }
  const gradeColor = gradeColors[threat.grade as string] || 'var(--text-secondary)'

  return (
    <div style={{ animation: 'fadeInUp 0.5s var(--ease-out)' }}>
      {/* ─── Threat Score Banner ─── */}
      <div style={{ ...styles.card, padding: 32, marginBottom: 24, borderColor: gradeColor, borderWidth: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 32, flexWrap: 'wrap' }}>

          {/* Score circle */}
          <div style={{ position: 'relative', width: 120, height: 120, flexShrink: 0 }}>
            <svg width="120" height="120" viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border-subtle)" strokeWidth="8" />
              <circle
                cx="60" cy="60" r="52"
                fill="none"
                stroke={gradeColor}
                strokeWidth="8"
                strokeDasharray={`${((threat.score ?? 0) / 100) * 327} 327`}
                strokeLinecap="round"
                transform="rotate(-90 60 60)"
                style={{ transition: 'stroke-dasharray 1s var(--ease-out)' }}
              />
            </svg>
            <div style={{
              position: 'absolute', inset: 0,
              display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center',
            }}>
              <span style={{ fontSize: 32, fontWeight: 800, color: gradeColor }} className="mono">
                {threat.score ?? '—'}
              </span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>/ 100</span>
            </div>
          </div>

          {/* App info */}
          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
              {threat.grade && (
                <span style={{
                  ...styles.gradeBadge,
                  background: gradeColor,
                  color: '#fff',
                }}>
                  {threat.grade}
                </span>
              )}
              <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                {threat.verdict ?? 'Unknown'}
              </span>
            </div>
            <h2 style={{ fontSize: 20, fontWeight: 700 }}>
              {apk.app_name ?? meta.filename ?? 'Unknown APK'}
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 4 }} className="mono">
              {apk.package_name ?? 'unknown.package'}
            </p>
            <div style={{ display: 'flex', gap: 16, marginTop: 12, flexWrap: 'wrap' }}>
              <MiniStat label="Size" value={meta.size_mb ? `${meta.size_mb} MB` : 'N/A'} />
              <MiniStat label="Version" value={apk.version_name ?? 'N/A'} />
              <MiniStat label="SDK" value={apk.min_sdk ? `${apk.min_sdk}–${apk.target_sdk}` : 'N/A'} />
              <MiniStat label="Permissions" value={String(apk.permissions?.length ?? 0)} />
            </div>
          </div>

          {/* Risk factors */}
          <div style={{ minWidth: 260 }}>
            <h4 style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
              Risk Factors
            </h4>
            {factors.length === 0 && (
              <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>None identified</p>
            )}
            {factors.slice(0, 4).map((f, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 6 }}>
                <span style={{ color: 'var(--accent-red)', fontSize: 10, marginTop: 4 }}>●</span>
                <span style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.4 }}>{f}</span>
              </div>
            ))}
            {factors.length > 4 && (
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                +{factors.length - 4} more factors
              </span>
            )}
          </div>

          {/* Action Buttons */}
          <div style={{ alignSelf: 'flex-start', marginLeft: 'auto' }} className="no-print">
            <button
               onClick={() => window.print()}
               style={{
                 background: 'var(--accent-cyan)',
                 color: '#000',
                 border: 'none',
                 padding: '8px 16px',
                 borderRadius: 4,
                 fontWeight: 600,
                 cursor: 'pointer',
                 display: 'flex',
                 alignItems: 'center',
                 gap: 8,
                 fontSize: 13
               }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                  <polyline points="7 10 12 15 17 10"></polyline>
                  <line x1="12" y1="15" x2="12" y2="3"></line>
              </svg>
              Export PDF Report
            </button>
          </div>
        </div>
      </div>

      {/* ─── Tabs ─── */}
      <div style={styles.tabBar} className="tab-bar-print-hide">
        {tabs.map((t) => (
          <button
            key={t.id}
            style={{
              ...styles.tab,
              borderColor: activeTab === t.id ? 'var(--accent-cyan)' : 'transparent',
              color: activeTab === t.id ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            }}
            onClick={() => onTabChange(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ─── Tab content ─── */}
      <div style={{ marginTop: 24 }}>
        {activeTab === 'overview' && <OverviewTab results={results} />}
        {activeTab === 'permissions' && <PermissionsTab data={results.permissions ?? {}} />}
        {activeTab === 'iocs' && <IOCsTab data={results.iocs ?? {}} />}
        {activeTab === 'network' && <NetworkTab data={results.dynamic_analysis ?? {}} />}
        {activeTab === 'manifest' && <ManifestTab data={results.manifest ?? {}} />}
        {activeTab === 'code' && <CodeTab data={results.code_analysis ?? {}} packer={results.packer_analysis ?? {}} />}
        {activeTab === 'droppers' && <DroppersTab data={results.nested_analysis ?? {}} />}
        {activeTab === 'certificate' && <CertificateTab data={results.certificate ?? {}} />}
        {activeTab === 'files' && <FilesTab files={results.file_tree ?? []} />}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   TAB COMPONENTS
   ═══════════════════════════════════════════════════════════════ */
function OverviewTab({ results }: { results: AnalysisResults }) {
  const meta = results.file_metadata ?? {}
  const apk = results.apk_metadata ?? {}
  const iocSummary = results.iocs?.summary ?? {}

  return (
    <div style={styles.gridTwo}>
      {/* Hashes */}
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Forensic Hashes</h3>
        {meta.hashes
          ? Object.entries(meta.hashes).map(([algo, hash]) => (
            <div key={algo} style={{ marginBottom: 10 }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>{algo}</span>
              <p style={{ fontSize: 12, wordBreak: 'break-all', color: 'var(--text-secondary)', marginTop: 2 }} className="mono">
                {hash as string}
              </p>
            </div>
          ))
          : <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No hash data</p>}
      </div>

      {/* Quick stats */}
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Analysis Summary</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <StatBox label="Activities" value={String(apk.activities?.length ?? 0)} color="var(--accent-blue)" />
          <StatBox label="Services" value={String(apk.services?.length ?? 0)} color="var(--accent-purple)" />
          <StatBox label="Receivers" value={String(apk.receivers?.length ?? 0)} color="var(--accent-orange)" />
          <StatBox label="IOCs Found" value={String(iocSummary.total_iocs ?? 0)} color="var(--accent-red)" />
        </div>
      </div>

      {/* APK contents */}
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>APK Contents</h3>
        <StatBox label="DEX Files" value={String(results.dex_files?.length ?? 0)} color="var(--accent-cyan)" />
        <div style={{ marginTop: 12 }}>
          <StatBox label="Native Libs" value={String(results.native_libs?.length ?? 0)} color="var(--accent-orange)" />
        </div>
        <div style={{ marginTop: 12 }}>
          <StatBox label="Total Files" value={String(results.file_tree?.length ?? 0)} color="var(--accent-blue)" />
        </div>
      </div>

      {/* Investigation notes */}
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Investigation Notes</h3>
        {results.certificate?.attribution_clues?.investigation_notes?.length
          ? results.certificate.attribution_clues.investigation_notes.map((note: string, i: number) => (
            <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
              <span style={{ color: 'var(--accent-orange)', fontSize: 14 }}>📌</span>
              <span style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{note}</span>
            </div>
          ))
          : <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No notes available</p>}
      </div>
    </div>
  )
}

function PermissionsTab({ data }: { data: any }) {
  const sevColors: Record<string, string> = {
    CRITICAL: 'var(--accent-red)',
    DANGEROUS: 'var(--accent-orange)',
    NORMAL: 'var(--text-muted)',
  }

  if (!data || Object.keys(data).length === 0) {
    return (
      <div style={styles.card}>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
          Permission data unavailable — Androguard may have failed to parse this APK.
        </p>
      </div>
    )
  }

  return (
    <div>
      {/* Risk bar */}
      <div style={{ ...styles.card, marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
          <span style={{ fontSize: 14, fontWeight: 600 }}>Permission Risk Score</span>
          <span className="mono" style={{ fontWeight: 700, color: 'var(--accent-orange)' }}>
            {data.risk_percentage ?? 0}%
          </span>
        </div>
        <div style={styles.progressTrack}>
          <div style={{ ...styles.progressFill, width: `${data.risk_percentage ?? 0}%`, background: 'var(--accent-orange)' }} />
        </div>
      </div>

      {/* Dangerous combos */}
      {data.dangerous_combinations?.length > 0 && (
        <div style={{ ...styles.card, marginBottom: 20, borderColor: 'var(--accent-red)' }}>
          <h3 style={{ ...styles.cardTitle, color: 'var(--accent-red)' }}>⚠️ Dangerous Combinations</h3>
          {data.dangerous_combinations.map((combo: any, i: number) => (
            <div key={i} style={{ padding: '12px 0', borderBottom: i < data.dangerous_combinations.length - 1 ? '1px solid var(--border-subtle)' : 'none' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ ...styles.severityDot, background: 'var(--accent-red)' }} />
                <span style={{ fontWeight: 600, fontSize: 14 }}>{combo.name}</span>
                <span style={{ ...styles.smallBadge, background: 'var(--accent-red-dim)', color: 'var(--accent-red)' }}>
                  {combo.severity}
                </span>
              </div>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4, marginLeft: 18 }}>
                {combo.forensic_significance}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Permission lists */}
      <div style={styles.gridTwo}>
        {Object.entries(data.categorized ?? {}).map(([severity, perms]) => (
          <div key={severity} style={styles.card}>
            <h3 style={{ ...styles.cardTitle, color: sevColors[severity] ?? 'var(--text-primary)' }}>
              {severity} ({(perms as string[]).length})
            </h3>
            {(perms as string[]).map((p, i) => (
              <div key={i} style={{ padding: '6px 0', fontSize: 12, color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-subtle)' }} className="mono">
                {p.replace('android.permission.', '')}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}

function IOCsTab({ data }: { data: any }) {
  const iocs = data.iocs ?? {}
  const iocLabels: Record<string, { icon: string; label: string; color: string }> = {
    ipv4_address: { icon: '🌐', label: 'IP Addresses', color: 'var(--accent-red)' },
    domain: { icon: '🔗', label: 'Domains', color: 'var(--accent-orange)' },
    url_full: { icon: '📡', label: 'Full URLs', color: 'var(--accent-orange)' },
    api_key_generic: { icon: '🔑', label: 'API Keys', color: 'var(--accent-red)' },
    email_address: { icon: '📧', label: 'Emails', color: 'var(--accent-blue)' },
    crypto_bitcoin: { icon: '₿', label: 'Bitcoin Wallets', color: 'var(--accent-red)' },
  }

  return (
    <div>
      <div style={{ ...styles.card, marginBottom: 20 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
          <StatBox label="Total IOCs" value={String(data.summary?.total_iocs ?? 0)} color="var(--accent-cyan)" />
          <StatBox label="Critical" value={String(data.summary?.critical_count ?? 0)} color="var(--accent-red)" />
          <StatBox label="C2 Indicators" value={data.summary?.has_c2_indicators ? 'YES' : 'NO'}
            color={data.summary?.has_c2_indicators ? 'var(--accent-red)' : 'var(--accent-cyan)'} />
          <StatBox label="Financial" value={data.summary?.has_financial_indicators ? 'YES' : 'NO'}
            color={data.summary?.has_financial_indicators ? 'var(--accent-red)' : 'var(--accent-cyan)'} />
        </div>
      </div>

      {Object.entries(iocs).map(([type, findings]) => {
        const meta = iocLabels[type]
        if (!meta || !(findings as any[]).length) return null
        return (
          <div key={type} style={{ ...styles.card, marginBottom: 16 }}>
            <h3 style={{ ...styles.cardTitle, color: meta.color }}>
              {meta.icon} {meta.label} ({(findings as any[]).length})
            </h3>
            {(findings as any[]).map((f: any, i: number) => (
              <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span className="mono" style={{ fontSize: 13, color: meta.color }}>{f.value}</span>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                  Source: {f.source}{f.investigation_note ? ` • ${f.investigation_note}` : ''}
                </div>
              </div>
            ))}
          </div>
        )
      })}
    </div>
  )
}

function NetworkTab({ data }: { data: any }) {
  const traffic = data.network_traffic ?? {}
  if (!traffic || Object.keys(traffic).length === 0 || traffic.error) {
    return (
      <div style={styles.card}>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
          {traffic.error || "No dynamic network traffic captured (Dynamic analysis may have been skipped or failed)."}
        </p>
      </div>
    )
  }

  const dns = traffic.dns_queries ?? []
  const ips = traffic.unique_ips ?? []
  const http = traffic.http_requests ?? []
  
  return (
    <div>
        <div style={{ ...styles.card, marginBottom: 20 }}>
            <h3 style={styles.cardTitle}>Dynamic PCAP Capture</h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
                <StatBox label="Total Packets" value={String(traffic.summary?.total_packets ?? 0)} color="var(--accent-blue)" />
                <StatBox label="Unique IPs" value={String(traffic.summary?.unique_ips_count ?? 0)} color="var(--accent-cyan)" />
                <StatBox label="DNS Queries" value={String(traffic.summary?.dns_query_count ?? 0)} color="var(--accent-orange)" />
                <StatBox label="HTTP Requests" value={String(traffic.summary?.http_request_count ?? 0)} color="var(--accent-red)" />
            </div>
        </div>

        {dns.length > 0 && (
            <div style={{ ...styles.card, marginBottom: 20, borderColor: 'var(--accent-orange)' }}>
                <h3 style={{ ...styles.cardTitle, color: 'var(--accent-orange)' }}>📡 C2 DNS Beacons</h3>
                {dns.map((q: string, i: number) => (
                    <div key={i} className="mono" style={{ padding: '6px 0', fontSize: 13, color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-subtle)' }}>
                        {q}
                    </div>
                ))}
            </div>
        )}

        {ips.length > 0 && (
            <div style={{ ...styles.card, marginBottom: 20 }}>
                <h3 style={{ ...styles.cardTitle }}>🌐 Contacted IP Addresses</h3>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                    {ips.map((ip: string, i: number) => (
                        <div key={i} className="mono" style={{ padding: '4px', fontSize: 13, color: 'var(--accent-cyan)' }}>
                            {ip}
                        </div>
                    ))}
                </div>
            </div>
        )}

        {http.length > 0 && (
            <div style={{ ...styles.card, marginBottom: 20, borderColor: 'var(--accent-red)' }}>
                <h3 style={{ ...styles.cardTitle, color: 'var(--accent-red)' }}>🔌 Captured HTTP Requests</h3>
                {http.map((req: any, i: number) => (
                    <div key={i} style={{ padding: '12px 0', borderBottom: i < http.length - 1 ? '1px solid var(--border-subtle)' : 'none' }}>
                        <div className="mono" style={{ fontWeight: 600, fontSize: 13, color: 'var(--accent-red)' }}>
                            {req.request}
                        </div>
                        <div className="mono" style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
                            Host: {req.host}
                        </div>
                    </div>
                ))}
            </div>
        )}
    </div>
  )
}

function ManifestTab({ data }: { data: any }) {
  const comps = data.components ?? {}
  const exported = data.exported_attack_surface ?? {}
  const misconfigs: any[] = data.misconfigurations ?? []

  if (!data || Object.keys(data).length === 0) {
    return (
      <div style={styles.card}>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
          Manifest data unavailable — Androguard may have failed to parse this APK.
        </p>
      </div>
    )
  }

  return (
    <div>
      {misconfigs.length > 0 && (
        <div style={{ ...styles.card, marginBottom: 20, borderColor: 'var(--accent-orange)' }}>
          <h3 style={{ ...styles.cardTitle, color: 'var(--accent-orange)' }}>⚠️ Misconfigurations</h3>
          {misconfigs.map((m: any, i: number) => (
            <div key={i} style={{ padding: '8px 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={{
                  ...styles.smallBadge,
                  background: m.severity === 'HIGH' ? 'var(--accent-red-dim)' : 'var(--accent-yellow-dim)',
                  color: m.severity === 'HIGH' ? 'var(--accent-red)' : 'var(--accent-yellow)',
                }}>
                  {m.severity}
                </span>
                <span style={{ fontWeight: 600, fontSize: 13 }}>{m.type}</span>
              </div>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>{m.description}</p>
            </div>
          ))}
        </div>
      )}

      <div style={{ ...styles.card, marginBottom: 20 }}>
        <h3 style={styles.cardTitle}>Exported Attack Surface</h3>
        {(['activities', 'services', 'receivers', 'providers'] as const).map((type) => {
          const items = exported[type] ?? []
          if (!items.length) return null
          return (
            <div key={type} style={{ marginBottom: 12 }}>
              <span style={{ fontSize: 12, color: 'var(--accent-orange)', textTransform: 'uppercase', fontWeight: 600 }}>
                {type} ({items.length})
              </span>
              {items.map((item: any, i: number) => (
                <div key={i} className="mono" style={{ fontSize: 12, color: 'var(--text-secondary)', padding: '4px 0 4px 16px' }}>
                  → {item.name}
                </div>
              ))}
            </div>
          )
        })}
      </div>

      <div style={styles.gridTwo}>
        {Object.entries(comps).map(([type, items]) => (
          <div key={type} style={styles.card}>
            <h3 style={styles.cardTitle}>
              {type.charAt(0).toUpperCase() + type.slice(1)} ({(items as any[]).length})
            </h3>
            {(items as any[]).map((item: any, i: number) => (
              <div key={i} style={{ padding: '4px 0', fontSize: 12, color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-subtle)' }} className="mono">
                {item.name}
                {item.exported && (
                  <span style={{ color: 'var(--accent-red)', marginLeft: 6, fontSize: 10 }}>EXPORTED</span>
                )}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}

function CodeTab({ data, packer }: { data: any, packer: any }) {
  if (!data || Object.keys(data).length === 0) {
    return (
      <div style={styles.card}>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
          Code analysis data unavailable — Androguard may have failed to parse this APK.
        </p>
      </div>
    )
  }

  return (
    <div>
      {/* PACKER ANALYSIS SECTION */}
      {packer.is_packed && (
          <div style={{ ...styles.card, marginBottom: 20, borderColor: 'var(--accent-red)' }}>
            <h3 style={{ ...styles.cardTitle, color: 'var(--accent-red)' }}>🚨 Commercial/Malware Packer Detected</h3>
            <div style={{ padding: '12px', background: 'var(--accent-red-dim)', borderRadius: 'var(--radius-sm)' }}>
              <p style={{ fontWeight: 600, fontSize: 15, color: 'var(--accent-red)' }}>
                {packer.detected_packers?.join(', ')}
              </p>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 8 }}>
                This application uses advanced anti-analysis and packing tools to hide its true payload. Static analysis of the classes.dex file will likely only reveal the unpacking stub.
              </p>
            </div>
          </div>
      )}

      {packer.encrypted_blobs && packer.encrypted_blobs.length > 0 && (
          <div style={{ ...styles.card, marginBottom: 20, borderColor: 'var(--accent-orange)' }}>
            <h3 style={{ ...styles.cardTitle, color: 'var(--accent-orange)' }}>📦 Encrypted Asset Blobs Found</h3>
            {packer.encrypted_blobs.map((blob: any, i: number) => (
                <div key={i} style={{ padding: '12px 0', borderBottom: i < packer.encrypted_blobs.length - 1 ? '1px solid var(--border-subtle)' : 'none' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontWeight: 600, fontSize: 14 }}>{blob.path}</span>
                    <span className="mono" style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
                      {blob.size_kb} KB
                    </span>
                  </div>
                  <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
                    Entropy: <span style={{ color: blob.entropy > 7.5 ? 'var(--accent-orange)' : 'var(--text-muted)' }}>{blob.entropy} (Highly Compressed/Encrypted)</span>
                  </p>
                  {blob.xor_header_hits && blob.xor_header_hits.length > 0 && (
                      <div style={{ marginTop: 8, padding: '8px', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-sm)' }}>
                        <span style={{ fontSize: 12, color: 'var(--accent-red)', fontWeight: 600 }}>⚠️ XOR Obfuscation Defeated:</span>
                        {blob.xor_header_hits.map((hit: any, j: number) => (
                            <p key={j} className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4, paddingLeft: 12 }}>
                              Key {hit.key_hex} reveals: {hit.revealed_type}
                            </p>
                        ))}
                      </div>
                  )}
                </div>
            ))}
          </div>
      )}

      <div style={{ ...styles.card, marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <h3 style={styles.cardTitle}>Code Risk Score</h3>
          <span className="mono" style={{ fontSize: 28, fontWeight: 800, color: 'var(--accent-orange)' }}>
            {data.code_risk_score ?? 0}/100
          </span>
        </div>
        <div style={styles.progressTrack}>
          <div style={{ ...styles.progressFill, width: `${data.code_risk_score ?? 0}%`, background: 'var(--accent-orange)' }} />
        </div>
        {data.obfuscation?.is_obfuscated && (
          <div style={{ marginTop: 12, padding: '8px 12px', background: 'var(--accent-orange-dim)', borderRadius: 'var(--radius-sm)', fontSize: 13 }}>
            🔒 Basic Obfuscation: {data.obfuscation.obfuscation_percentage}% • {data.obfuscation.detected_packers?.join(', ')}
          </div>
        )}
      </div>

      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Detected Code Capabilities</h3>
        {data.capabilities?.length
          ? data.capabilities.map((cap: any, i: number) => {
            const riskColors: Record<string, string> = {
              CRITICAL: 'var(--accent-red)',
              HIGH: 'var(--accent-orange)',
              MEDIUM: 'var(--accent-yellow)',
              LOW: 'var(--accent-cyan)',
            }
            return (
              <div key={i} style={{ padding: '10px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ ...styles.smallBadge, background: `${riskColors[cap.risk] ?? '#888'}20`, color: riskColors[cap.risk] ?? '#888' }}>
                    {cap.risk}
                  </span>
                  <span style={{ fontWeight: 600, fontSize: 14 }}>{cap.capability}</span>
                  <span className="mono" style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
                    {cap.evidence_count} hits
                  </span>
                </div>
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4, marginLeft: 18 }}>
                  {cap.description}
                </p>
              </div>
            )
          })
          : <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No capabilities detected</p>}
      </div>
    </div>
  )
}

function DroppersTab({ data }: { data: any }) {
  if (!data || Object.keys(data).length === 0) {
    return (
      <div style={styles.card}>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
          No nested payloads or dropper configurations detected.
        </p>
      </div>
    )
  }

  const conf = data.dropper_indicators?.dropper_confidence ?? 0;
  
  return (
    <div>
        <div style={{ ...styles.card, marginBottom: 20, borderColor: conf >= 40 ? 'var(--accent-red)' : 'var(--border-subtle)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h3 style={{ ...styles.cardTitle, color: conf >= 40 ? 'var(--accent-red)' : 'var(--text-primary)', marginBottom: 4 }}>
                  Dropper / Loader Assessment
              </h3>
              <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
                  {data.dropper_indicators?.classification ?? 'Unknown'}
              </p>
            </div>
            <div style={{ textAlign: 'right' }}>
                <span className="mono" style={{ fontSize: 24, fontWeight: 700, color: conf >= 40 ? 'var(--accent-red)' : 'var(--accent-orange)' }}>
                    {conf}%
                </span>
                <p style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Confidence</p>
            </div>
          </div>
        </div>

        <div style={styles.card}>
            <h3 style={styles.cardTitle}>Hidden Payloads Discovered ({data.payloads?.length ?? 0})</h3>
            {data.payloads?.map((payload: any, i: number) => (
                <div key={i} style={{ 
                    padding: '12px 16px', 
                    marginBottom: 8,
                    borderRadius: 6,
                    border: payload.is_primary_payload ? '1px solid var(--accent-red)' : '1px solid var(--border-subtle)',
                    background: payload.is_primary_payload ? 'var(--accent-red-dim)' : 'transparent'
                }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        {payload.is_primary_payload && (
                            <span style={{ padding: '2px 6px', background: 'var(--accent-red)', color: '#000', fontSize: 10, borderRadius: 4, fontWeight: 800 }}>
                                ☠️ CONFIRMED TROJAN PAYLOAD
                            </span>
                        )}
                        {payload.is_disguised && (
                            <span style={{ padding: '2px 6px', background: 'rgba(239, 71, 111, 0.3)', color: 'var(--accent-red)', fontSize: 10, borderRadius: 4, fontWeight: 600 }}>
                                DISGUISED
                            </span>
                        )}
                        <span className="mono" style={{ fontWeight: payload.is_primary_payload ? 700 : 600, fontSize: 13, color: payload.is_primary_payload ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                            {payload.source_path}
                        </span>
                    </div>
                    <div style={{ display: 'flex', gap: 16, marginTop: 8 }}>
                        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Type: <strong style={{ color: 'var(--text-primary)' }}>{payload.file_type}</strong></span>
                        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Size: <strong style={{ color: 'var(--text-primary)' }}>{payload.size_kb} KB</strong></span>
                        {payload.entropy && (
                            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Entropy: <strong style={{ color: payload.entropy > 7.5 ? 'var(--accent-orange)' : 'var(--text-primary)' }}>{payload.entropy.toFixed(2)}</strong></span>
                        )}
                    </div>
                </div>
            ))}
        </div>
    </div>
  )
}

function CertificateTab({ data }: { data: any }) {
  const cert = data.certificates?.[0]
  if (!cert) {
    return (
      <div style={styles.card}>
        <p style={{ color: 'var(--text-muted)' }}>
          {data && Object.keys(data).length === 0
            ? 'Certificate data unavailable — Androguard may have failed to parse this APK.'
            : 'No certificate data'}
        </p>
      </div>
    )
  }

  const subject = cert.subject ?? {}
  const validity = cert.validity ?? {}

  return (
    <div style={styles.gridTwo}>
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Certificate Subject</h3>
        <InfoRow label="Common Name" value={subject.common_name} />
        <InfoRow label="Organization" value={subject.organization} />
        <InfoRow label="Country" value={subject.country} />
        <InfoRow label="Email" value={subject.email} />
      </div>
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Certificate Details</h3>
        <InfoRow label="Valid From" value={validity.not_before} />
        <InfoRow label="Valid Until" value={validity.not_after} />
        <InfoRow label="Signing Scheme" value={data.signing_scheme} />
        <InfoRow label="Self-Signed" value={String(data.is_self_signed ?? false)} alert={data.is_self_signed} />
        <InfoRow label="Debug Cert" value={String(data.is_debug_signed ?? false)} alert={data.is_debug_signed} />
      </div>
      <div style={{ ...styles.card, gridColumn: '1 / -1' }}>
        <h3 style={styles.cardTitle}>SHA-256 Fingerprint</h3>
        <p className="mono" style={{ fontSize: 12, color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>
          {cert.hashes?.sha256 ?? 'N/A'}
        </p>
      </div>
    </div>
  )
}

function FilesTab({ files }: { files: any[] }) {
  const suspicious = files.filter((f) => f.suspicious)

  return (
    <div>
      {suspicious.length > 0 && (
        <div style={{ ...styles.card, marginBottom: 20, borderColor: 'var(--accent-red)' }}>
          <h3 style={{ ...styles.cardTitle, color: 'var(--accent-red)' }}>🚨 Suspicious Files</h3>
          {suspicious.map((f, i) => (
            <div key={i} className="mono" style={{ padding: '6px 0', fontSize: 12, color: 'var(--accent-red)', borderBottom: '1px solid var(--border-subtle)' }}>
              {f.path}{' '}
              <span style={{ color: 'var(--text-muted)' }}>({(f.size / 1024).toFixed(1)} KB)</span>
            </div>
          ))}
        </div>
      )}

      <div style={styles.card}>
        <h3 style={styles.cardTitle}>All Files ({files.length})</h3>
        {files.length === 0
          ? <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No file data available</p>
          : (
            <div style={{ maxHeight: 400, overflowY: 'auto' }}>
              {files.map((f, i) => (
                <div key={i} style={{
                  display: 'flex', justifyContent: 'space-between', padding: '5px 0',
                  borderBottom: '1px solid var(--border-subtle)', fontSize: 12,
                }}>
                  <span className="mono" style={{ color: f.suspicious ? 'var(--accent-red)' : 'var(--text-secondary)' }}>
                    {f.suspicious && '⚠ '}{f.path}
                  </span>
                  <span style={{ color: 'var(--text-muted)', flexShrink: 0 }} className="mono">
                    {(f.size / 1024).toFixed(1)} KB
                    {f.flag && (
                      <span style={{ marginLeft: 8, color: 'var(--accent-yellow)', fontSize: 10 }}>{f.flag}</span>
                    )}
                  </span>
                </div>
              ))}
            </div>
          )}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   SMALL REUSABLE COMPONENTS
   ═══════════════════════════════════════════════════════════════ */
function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block' }}>{label}</span>
      <span className="mono" style={{ fontSize: 13, fontWeight: 600 }}>{value}</span>
    </div>
  )
}

function StatBox({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div style={{ padding: 12, background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
      <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>{label}</span>
      <span className="mono" style={{ fontSize: 20, fontWeight: 700, color }}>{value}</span>
    </div>
  )
}

function InfoRow({ label, value, alert }: { label: string; value?: string; alert?: boolean }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border-subtle)' }}>
      <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{label}</span>
      <span className="mono" style={{ fontSize: 13, color: alert ? 'var(--accent-red)' : 'var(--text-secondary)' }}>
        {value ?? 'N/A'}
      </span>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   STYLES
   ═══════════════════════════════════════════════════════════════ */
const styles: Record<string, React.CSSProperties> = {
  navbar: {
    position: 'sticky', top: 0, zIndex: 100,
    background: 'rgba(10, 14, 26, 0.85)',
    backdropFilter: 'blur(16px)',
    borderBottom: '1px solid var(--border-subtle)',
    padding: '0 24px',
  },
  navInner: {
    maxWidth: 1200, margin: '0 auto',
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    height: 56,
  },
  logoIcon: {
    width: 36, height: 36,
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    borderRadius: 'var(--radius-sm)',
    background: 'var(--accent-cyan-dim)',
    color: 'var(--accent-cyan)',
  },
  logoText: { fontSize: 18, fontWeight: 700, letterSpacing: '-0.3px' },
  badge: {
    fontSize: 10, fontWeight: 600,
    padding: '2px 6px', borderRadius: 'var(--radius-full)',
    background: 'var(--accent-cyan-dim)', color: 'var(--accent-cyan)',
  },
  navButton: {
    padding: '6px 14px', fontSize: 13, fontWeight: 500,
    background: 'var(--bg-tertiary)', color: 'var(--text-primary)',
    border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
  },
  main: { maxWidth: 1200, margin: '0 auto', padding: '40px 24px 80px' },
  heroIconWrap: {
    position: 'relative' as const,
    width: 88, height: 88, margin: '0 auto 24px',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    background: 'var(--accent-cyan-dim)', borderRadius: '50%',
  },
  heroRing: {
    position: 'absolute' as const, inset: -6,
    border: '2px solid var(--accent-cyan)', borderRadius: '50%',
    opacity: 0.3, animation: 'pulse-ring 2.5s ease-out infinite',
  },
  heroTitle: {
    fontSize: 36, fontWeight: 800, letterSpacing: '-1px',
    background: 'linear-gradient(135deg, var(--accent-cyan), var(--accent-blue))',
    WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
  },
  heroSub: {
    color: 'var(--text-secondary)', fontSize: 16, lineHeight: 1.6,
    maxWidth: 520, margin: '12px auto 0',
  },
  dropZone: {
    padding: '48px 24px', borderRadius: 'var(--radius-lg)',
    border: '2px dashed var(--border-light)',
    textAlign: 'center' as const, cursor: 'pointer',
    transition: 'all 0.3s var(--ease-out)',
  },
  fileIcon: { fontSize: 48, marginBottom: 12 },
  uploadIcon: { color: 'var(--text-muted)', marginBottom: 16 },
  analyzeBtn: {
    width: '100%', marginTop: 20, padding: '14px 24px',
    fontSize: 15, fontWeight: 600,
    background: 'linear-gradient(135deg, var(--accent-cyan), var(--accent-blue))',
    color: '#fff', border: 'none', borderRadius: 'var(--radius-md)',
    cursor: 'pointer',
    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
    transition: 'transform 0.2s, box-shadow 0.3s',
  },
  featureGrid: {
    display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginTop: 48,
  },
  featureCard: {
    padding: 20, background: 'var(--bg-card)',
    borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)',
    textAlign: 'center' as const,
  },
  spinnerWrap: {
    position: 'relative' as const, width: 80, height: 80, margin: '0 auto',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
  },
  spinner: {
    position: 'absolute' as const, inset: 0,
    border: '3px solid var(--border-subtle)', borderTopColor: 'var(--accent-cyan)',
    borderRadius: '50%', animation: 'rotate 1s linear infinite',
  },
  progressTrack: {
    height: 6, background: 'var(--bg-tertiary)',
    borderRadius: 'var(--radius-full)', overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-blue))',
    borderRadius: 'var(--radius-full)', transition: 'width 0.5s var(--ease-out)',
  },
  moduleRow: {
    display: 'flex', alignItems: 'center', gap: 12,
    padding: '10px 14px', borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border-subtle)', transition: 'all 0.3s',
  },
  card: {
    background: 'var(--bg-card)', borderRadius: 'var(--radius-lg)',
    border: '1px solid var(--border-subtle)', padding: 24,
  },
  cardTitle: { fontSize: 14, fontWeight: 600, marginBottom: 16, color: 'var(--text-primary)' },
  gridTwo: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 },
  tabBar: {
    display: 'flex', gap: 4, overflowX: 'auto',
    borderBottom: '1px solid var(--border-subtle)', paddingBottom: 0,
  },
  tab: {
    padding: '10px 16px', fontSize: 13, fontWeight: 500,
    background: 'none', border: 'none',
    borderBottom: '2px solid transparent', cursor: 'pointer',
    whiteSpace: 'nowrap', transition: 'all 0.2s',
  },
  gradeBadge: {
    padding: '4px 12px', borderRadius: 'var(--radius-full)',
    fontSize: 12, fontWeight: 700, letterSpacing: 0.5,
  },
  smallBadge: { padding: '2px 8px', borderRadius: 'var(--radius-full)', fontSize: 10, fontWeight: 600 },
  severityDot: { width: 8, height: 8, borderRadius: '50%', flexShrink: 0 },
}
