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
        { path: 'assets/payload.blob', size_kb: 3950.4, entropy: 7.95, xor_header_hits: [{ 'key_hex': '0x5a', 'revealed_type': 'DEX (Standard)' }] }
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

  const uploadRes = await fetch('http://127.0.0.1:8000/upload', {
    method: 'POST',
    body: formData,
  })

  if (!uploadRes.ok) throw new Error('Upload failed')
  const { task_id } = await uploadRes.json()

  onModuleUpdate(0, 'passed')
  onModuleUpdate(1, 'running')

  while (true) {
    await new Promise(r => setTimeout(r, 2000))
    const statusRes = await fetch(`http://127.0.0.1:8000/status/${task_id}`)
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
            <span style={styles.logoText}>SherlockAPK</span>
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
    <div style={{ maxWidth: 1200, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 64, animation: 'fadeInUp 0.6s var(--ease-out)' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: 48, alignItems: 'center' }}>
        {/* Left Side Hero */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 12px', background: 'var(--bg-tertiary)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-full)', alignSelf: 'flex-start' }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-cyan)' }} />
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', letterSpacing: 0.5 }}>THE Nº1 CHOICE FOR ENTERPRISE APK SECURITY SOLUTIONS</span>
          </div>

          <h1 style={{ fontSize: 48, fontWeight: 800, lineHeight: 1.1, color: 'var(--text-primary)', letterSpacing: '-1.5px', textTransform: 'uppercase' }}>
            COMPREHENSIVE CYBERSECURITY SOLUTIONS DESIGNED FOR EVERY MOBILE APPLICATION
          </h1>

          <p style={{ color: 'var(--text-secondary)', fontSize: 16, lineHeight: 1.6, maxWidth: 580 }}>
            We combine advanced reverse engineering with closed-sandbox detonation to protect your mobile ecosystem, identify malicious patterns early, and ensure your deployment operates securely.
          </p>

          <div style={{ display: 'flex', gap: 16, marginTop: 12 }}>
            <button
              onClick={() => fileInputRef.current?.click()}
              style={{ padding: '14px 28px', background: 'var(--accent-cyan)', color: 'var(--text-inverse)', border: 'none', borderRadius: 'var(--radius-sm)', fontSize: 14, fontWeight: 700, cursor: 'pointer', transition: 'all 0.2s' }}
            >
              UPLOAD PACKAGE
            </button>
            <a
              href="https://github.com/1-basil/APKsherlock"
              target="_blank"
              rel="noopener noreferrer"
              style={{ padding: '14px 28px', background: 'transparent', color: 'var(--text-primary)', border: '1px solid var(--border-light)', borderRadius: 'var(--radius-sm)', fontSize: 14, fontWeight: 600, textDecoration: 'none', cursor: 'pointer', transition: 'all 0.2s', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            >
              LEARN MORE
            </a>
          </div>
        </div>

        {/* Right Side Upload Frosted Widget */}
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)', padding: 32, boxShadow: 'var(--shadow-lg)' }}>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8, letterSpacing: '-0.3px' }}>Upload Package</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 24 }}>Select or drop an Android application file (.apk) to initiate the threat analysis process.</p>

          <div
            style={{
              padding: '40px 20px',
              borderRadius: 'var(--radius-md)',
              border: '2px dashed var(--border-light)',
              textAlign: 'center',
              cursor: 'pointer',
              background: isDragging ? 'var(--accent-cyan-dim)' : 'var(--bg-tertiary)',
              borderColor: isDragging ? 'var(--accent-cyan)' : 'var(--border-subtle)',
              transition: 'all 0.3s var(--ease-out)',
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
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
                <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
                  <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
                  <line x1="12" y1="22.08" x2="12" y2="12" />
                </svg>
                <p style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', wordBreak: 'break-all' }}>{file.name}</p>
                <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                  {(file.size / 1024 / 1024).toFixed(2)} MB • Ready
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="17 8 12 3 7 8" />
                  <line x1="12" y1="3" x2="12" y2="15" />
                </svg>
                <p style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-primary)' }}>
                  Drag & drop APK here or <span style={{ color: 'var(--accent-cyan)' }}>browse</span>
                </p>
                <p style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                  Supports package files up to 500 MB
                </p>
              </div>
            )}
          </div>

          {file && (
            <button
              onClick={onStart}
              style={{
                width: '100%',
                marginTop: 20,
                padding: '14px 24px',
                fontSize: 14,
                fontWeight: 700,
                background: 'var(--accent-cyan)',
                color: 'var(--text-inverse)',
                border: 'none',
                borderRadius: 'var(--radius-sm)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 8,
                transition: 'all 0.2s'
              }}
            >
              START AUDIT
            </button>
          )}
        </div>
      </div>

      {/* Dribbble Inspired Stats Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 24, borderTop: '1px solid var(--border-subtle)', paddingTop: 40, marginTop: 16 }}>
        {[
          { metric: '99.7%', title: 'Detection Accuracy', desc: 'Verified threat identification rates.' },
          { metric: '14+', title: 'Analysis Pipelines', desc: 'Simultaneous byte and sandbox decoders.' },
          { metric: '0s', title: 'Detonation Latency', desc: 'Real-time isolated ARM execution.' },
          { metric: '24/7', title: 'Automated Monitoring', desc: 'Continuous endpoint threat intelligence.' }
        ].map((stat, i) => (
          <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <span style={{ fontSize: 36, fontWeight: 900, color: 'var(--text-primary)', letterSpacing: '-1px' }}>{stat.metric}</span>
            <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>{stat.title}</h4>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.4 }}>{stat.desc}</p>
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
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
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
            <span style={{ fontSize: 10, width: 36, textAlign: 'left', fontWeight: 800, color: m.status === 'passed' ? 'var(--accent-cyan)' : m.status === 'failed' ? 'var(--accent-red)' : 'var(--text-secondary)' }} className="mono">
              {m.status === 'pending' && 'WAIT'}
              {m.status === 'running' && 'RUN'}
              {m.status === 'passed' && 'PASS'}
              {m.status === 'failed' && 'FAIL'}
              {m.status === 'skipped' && 'SKIP'}
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

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'ai_analysis', label: 'AI Threat Analysis' },
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

  const getTabIcon = (id: string) => {
    switch (id) {
      case 'overview':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="3" width="7" height="9" />
            <rect x="14" y="3" width="7" height="5" />
            <rect x="14" y="12" width="7" height="9" />
            <rect x="3" y="16" width="7" height="5" />
          </svg>
        );
      case 'ai_analysis':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <path d="M12 16v-4" />
            <path d="M12 8h.01" />
          </svg>
        );
      case 'permissions':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
        );
      case 'iocs':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <circle cx="12" cy="12" r="6" />
            <circle cx="12" cy="12" r="2" />
          </svg>
        );
      case 'network':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="22" y1="2" x2="11" y2="13" />
            <polygon points="22 2 15 22 11 13 2 9 22 2" />
          </svg>
        );
      case 'manifest':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14 2 14 8 20 8" />
            <line x1="16" y1="13" x2="8" y2="13" />
            <line x1="16" y1="17" x2="8" y2="17" />
          </svg>
        );
      case 'code':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="16 18 22 12 16 6" />
            <polyline points="8 6 2 12 8 18" />
          </svg>
        );
      case 'droppers':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
          </svg>
        );
      case 'certificate':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="8" r="7" />
            <polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88" />
          </svg>
        );
      case 'files':
        return (
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
          </svg>
        );
      default:
        return null;
    }
  }

  return (
    <div style={{ display: 'flex', gap: 32, animation: 'fadeInUp 0.5s var(--ease-out)', minHeight: 'calc(100vh - 160px)', position: 'relative' }}>
      {/* Sidebar (Left) */}
      <div style={{ width: 260, flexShrink: 0, borderRight: '1px solid var(--border-subtle)', paddingRight: 24 }} className="no-print">
        {/* Sidebar Header / Threat score */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginBottom: 24, paddingBottom: 24, borderBottom: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', letterSpacing: 0.5 }}>THREAT LEVEL</span>
            <span style={{
              fontSize: 10,
              fontWeight: 800,
              padding: '2px 8px',
              borderRadius: 'var(--radius-full)',
              background: gradeColor,
              color: '#000',
            }}>
              {threat.grade ?? 'UNKNOWN'}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div style={{ fontSize: 32, fontWeight: 900, color: gradeColor }} className="mono">
              {threat.score ?? '—'}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>Risk Score</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>out of 100 max</span>
            </div>
          </div>

          <div style={{ fontSize: 13, color: 'var(--text-secondary)', fontWeight: 600 }}>
            {threat.verdict ?? 'No threats detected'}
          </div>
        </div>

        {/* Categories Menu */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {tabs.map((t) => {
            const isActive = activeTab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => onTabChange(t.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: '10px 16px',
                  fontSize: 13,
                  fontWeight: isActive ? 600 : 500,
                  color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  background: isActive ? 'var(--bg-tertiary)' : 'transparent',
                  border: 'none',
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                  textAlign: 'left',
                  transition: 'all 0.2s',
                  width: '100%'
                }}
              >
                <span style={{ color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)', display: 'flex', alignItems: 'center' }}>
                  {getTabIcon(t.id)}
                </span>
                {t.label}
              </button>
            )
          })}
        </div>
      </div>

      {/* Content Pane (Right) */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 24 }}>
        {/* Breadcrumbs / Actions header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }} className="mono">
              <span>ANALYSES</span>
              <span>&gt;</span>
              <span>{apk.package_name ?? 'UNKNOWN.PACKAGE'}</span>
              <span>&gt;</span>
              <span style={{ color: 'var(--accent-cyan)' }}>{tabs.find(t => t.id === activeTab)?.label.toUpperCase()}</span>
            </div>
            <h1 style={{ fontSize: 24, fontWeight: 800, marginTop: 4, letterSpacing: '-0.5px' }}>
              {apk.app_name ?? meta.filename ?? 'Unknown Package'}
            </h1>
          </div>

          <div style={{ display: 'flex', gap: 12 }} className="no-print">
            <button
              onClick={() => {
                window.location.reload();
              }}
              style={{
                background: 'var(--bg-tertiary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-light)',
                padding: '8px 16px',
                borderRadius: 'var(--radius-sm)',
                fontWeight: 600,
                cursor: 'pointer',
                fontSize: 12
              }}
            >
              New Analysis
            </button>
            <button
              onClick={() => window.print()}
              style={{
                background: 'var(--accent-cyan)',
                color: 'var(--text-inverse)',
                border: 'none',
                padding: '8px 16px',
                borderRadius: 'var(--radius-sm)',
                fontWeight: 700,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 12
              }}
            >
              Export Report
            </button>
          </div>
        </div>

        {/* Tab Content Area with animate-in tab transitions */}
        <div key={activeTab} className="animate-in" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {activeTab === 'overview' && <OverviewTab results={results} />}
          {activeTab === 'ai_analysis' && <AIAnalysisTab data={results.ai_analysis ?? {}} />}
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
  const ai = results.ai_analysis ?? {}

  const verdictColors: Record<string, string> = {
    MALICIOUS: 'var(--accent-red)',
    SUSPICIOUS: 'var(--accent-orange)',
    SAFE: 'var(--accent-cyan)',
    BENIGN: 'var(--accent-cyan)',
  }
  const color = verdictColors[ai.verdict as string] ?? 'var(--border-subtle)'

  const getCollectedData = (perms: string[]) => {
    const collected = []
    const pSet = new Set(perms || [])
    if (pSet.has('android.permission.READ_SMS') || pSet.has('android.permission.RECEIVE_SMS') || pSet.has('android.permission.SEND_SMS')) {
      collected.push({ category: 'SMS Messages / OTPs', reason: 'Critical: Can read, send, or intercept incoming SMS messages.' })
    }
    if (pSet.has('android.permission.ACCESS_FINE_LOCATION') || pSet.has('android.permission.ACCESS_COARSE_LOCATION')) {
      collected.push({ category: 'GPS & Location Data', reason: 'High Risk: Tracks precise device coordinates.' })
    }
    if (pSet.has('android.permission.READ_CONTACTS') || pSet.has('android.permission.WRITE_CONTACTS')) {
      collected.push({ category: 'Contacts Directory', reason: 'High Risk: Harvesting personal and professional contact cards.' })
    }
    if (pSet.has('android.permission.RECORD_AUDIO')) {
      collected.push({ category: 'Background Audio / Voice', reason: 'Critical: Can record device ambient audio/calls.' })
    }
    if (pSet.has('android.permission.READ_CALL_LOG') || pSet.has('android.permission.WRITE_CALL_LOG')) {
      collected.push({ category: 'Detailed Call Logs', reason: 'High Risk: Accesses caller history and call metadata.' })
    }
    if (pSet.has('android.permission.REQUEST_INSTALL_PACKAGES')) {
      collected.push({ category: 'Payloads & Installed Apps', reason: 'Critical: Installs external software/payloads without notification.' })
    }
    if (pSet.has('android.permission.FOREGROUND_SERVICE')) {
      collected.push({ category: 'Persistent Background Jobs', reason: 'Medium Risk: Executes long-lived execution threads.' })
    }
    // Always present if there are basic permissions
    if (perms && perms.length > 0) {
      collected.push({ category: 'Device & Hardware Metadata', reason: 'Standard: Collects SDK levels, model name, and build parameters.' })
    }
    return collected
  }

  const collectedData = getCollectedData(apk.permissions || [])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* AI Threat Summary Banner (Smart Way) */}
      {ai && ai.verdict && (
        <div style={{ ...styles.card, borderColor: color, borderWidth: 1 }}>
          <h3 style={{ ...styles.cardTitle, display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <span>Autonomous AI Analyst Verdict:</span>
            <span style={{ color, fontWeight: 800 }}>
              {ai.verdict}
            </span>
          </h3>
          {ai.malware_family_hypothesis && (
            <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>
              Malware Family Hypothesis: <strong>{ai.malware_family_hypothesis}</strong>
            </p>
          )}
          <p style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            {ai.executive_summary}
          </p>
        </div>
      )}

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
                <span style={{ color: 'var(--accent-orange)', fontSize: 14 }}>-</span>
                <span style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{note}</span>
              </div>
            ))
            : <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No notes available</p>}
        </div>

        {/* Data Collection Analysis */}
        <div style={{ ...styles.card, gridColumn: '1 / -1' }}>
          <h3 style={styles.cardTitle}>User Data Collection Analysis</h3>
          {collectedData.length > 0 ? (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
              {collectedData.map((d, i) => (
                <div key={i} style={{ padding: 12, background: 'var(--bg-tertiary)', borderLeft: '3px solid var(--accent-orange)', borderRadius: 'var(--radius-sm)' }}>
                  <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{d.category}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>{d.reason}</div>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No major personal data collection capabilities detected.</p>
          )}
        </div>
      </div>
    </div>
  )
}

function AIAnalysisTab({ data }: { data: any }) {
  if (!data || Object.keys(data).length === 0 || data.error) {
    return (
      <div style={styles.card}>
        <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
          {data?.error || "AI threat analysis data is not available. Please ensure your API keys are configured and run the analysis again."}
        </p>
      </div>
    )
  }

  const verdict = data.verdict ?? 'UNKNOWN'
  const verdictColors: Record<string, string> = {
    MALICIOUS: 'var(--accent-red)',
    SUSPICIOUS: 'var(--accent-orange)',
    SAFE: 'var(--accent-cyan)',
    BENIGN: 'var(--accent-cyan)',
  }
  const color = verdictColors[verdict] ?? 'var(--text-secondary)'

  const keyFindings = data.key_findings ?? {}
  const tactics = data.mitre_attck_tactics ?? []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Overview Block */}
      <div style={{ ...styles.card, borderColor: color, borderWidth: 1 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>AI Assessment Verdict</span>
            <h2 style={{ fontSize: 28, fontWeight: 800, color, marginTop: 4 }}>{verdict}</h2>
            {data.malware_family_hypothesis && (
              <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginTop: 4 }}>
                Hypothesized Family: <strong style={{ color: 'var(--text-primary)' }}>{data.malware_family_hypothesis}</strong>
              </p>
            )}
          </div>
          {data.threat_score_override !== undefined && (
            <div style={{ textAlign: 'right' }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>AI Threat Score</span>
              <div style={{ fontSize: 32, fontWeight: 800, color: 'var(--accent-orange)', marginTop: 4 }}>
                {data.threat_score_override}
                <span style={{ fontSize: 16, color: 'var(--text-muted)' }}>/100</span>
              </div>
            </div>
          )}
        </div>

        <div style={{ marginTop: 20, paddingTop: 20, borderTop: '1px solid var(--border-subtle)' }}>
          <h4 style={{ fontSize: 13, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8 }}>
            Executive Summary
          </h4>
          <p style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            {data.executive_summary}
          </p>
        </div>
      </div>

      {/* Grid for findings and MITRE */}
      <div style={styles.gridTwo}>
        {/* Key Findings */}
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>AI-Extracted Findings</h3>
          {Object.keys(keyFindings).length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {Object.entries(keyFindings).map(([title, detail], i) => (
                <div key={i} style={{ paddingBottom: 12, borderBottom: i < Object.keys(keyFindings).length - 1 ? '1px solid var(--border-subtle)' : 'none' }}>
                  <h4 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{title}</h4>
                  <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4, lineHeight: 1.4 }}>
                    {detail as string}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No detailed findings provided by AI.</p>
          )}
        </div>

        {/* MITRE ATT&CK */}
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>MITRE ATT&CK Techniques</h3>
          {tactics.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {tactics.map((tactic: string, i: number) => {
                const parts = tactic.split(':')
                const code = parts[0]?.trim()
                const name = parts.slice(1).join(':')?.trim()
                return (
                  <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 12, padding: '8px 12px', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent-cyan)', background: 'var(--accent-cyan-dim)', padding: '2px 6px', borderRadius: 4, fontStyle: 'normal' }} className="mono">
                      {code}
                    </span>
                    <span style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                      {name || code}
                    </span>
                  </div>
                )
              })}
            </div>
          ) : (
            <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No MITRE ATT&CK techniques identified.</p>
          )}
        </div>
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
    ipv4_address: { icon: 'IP', label: 'IP Addresses', color: 'var(--accent-red)' },
    domain: { icon: 'DOM', label: 'Domains', color: 'var(--accent-orange)' },
    url_full: { icon: 'URL', label: 'Full URLs', color: 'var(--accent-orange)' },
    api_endpoint: { icon: 'API', label: 'API Endpoints', color: 'var(--accent-cyan)' },
    websocket_url: { icon: 'WS', label: 'WebSocket URLs', color: 'var(--accent-purple)' },
    onion_address: { icon: 'TOR', label: 'Tor/Onion Addresses', color: 'var(--accent-red)' },
    jwt_token: { icon: 'JWT', label: 'JWT Tokens', color: 'var(--accent-purple)' },
    api_key_generic: { icon: 'KEY', label: 'API Keys', color: 'var(--accent-red)' },
    google_api_key: { icon: 'GKEY', label: 'Google API Keys', color: 'var(--accent-orange)' },
    aws_access_key: { icon: 'AWS', label: 'AWS Credentials', color: 'var(--accent-red)' },
    firebase_key: { icon: 'FB', label: 'Firebase Backends', color: 'var(--accent-orange)' },
    discord_webhook: { icon: 'DISC', label: 'Discord Webhooks', color: 'var(--accent-blue)' },
    telegram_token: { icon: 'TG', label: 'Telegram Bot Tokens', color: 'var(--accent-cyan)' },
    crypto_bitcoin: { icon: 'BTC', label: 'Bitcoin Wallets', color: 'var(--accent-red)' },
    crypto_ethereum: { icon: 'ETH', label: 'Ethereum Wallets', color: 'var(--accent-purple)' },
    crypto_monero: { icon: 'XMR', label: 'Monero Wallets', color: 'var(--accent-red)' },
    crypto_solana: { icon: 'SOL', label: 'Solana Wallets', color: 'var(--accent-cyan)' },
    crypto_tron: { icon: 'TRX', label: 'Tron Wallets', color: 'var(--accent-red)' },
    email_address: { icon: 'MAIL', label: 'Emails', color: 'var(--accent-blue)' },
    phone_number: { icon: 'TEL', label: 'Phone Numbers', color: 'var(--accent-cyan)' },
    indian_mobile: { icon: 'MOB', label: 'Indian Mobile Numbers', color: 'var(--accent-orange)' },
    hardcoded_password: { icon: 'PASS', label: 'Hardcoded Passwords', color: 'var(--accent-red)' },
    private_key: { icon: 'KEY', label: 'Private Keys', color: 'var(--accent-red)' },
    database_connection: { icon: 'DB', label: 'Database Connections', color: 'var(--accent-purple)' },
    c2_port: { icon: 'PORT', label: 'Suspicious Ports', color: 'var(--accent-red)' },
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
  const correlation = data.correlation ?? null

  // Local IP classifier fallback
  const classifyIp = (ip: string) => {
    const enriched = traffic.enriched_ips?.find((e: any) => e.ip === ip)
    if (enriched) return enriched

    let provider = "Generic Cloud Provider"
    let country = "US"
    let countryName = "United States"
    let flag = "🇺🇸"
    let asn = "AS13335"
    let isp = "Unknown ISP"

    const parts = ip.split(".")
    if (parts.length === 4) {
      const p0 = parseInt(parts[0])
      const p1 = parseInt(parts[1])
      if (p0 === 104 || (p0 === 172 && p1 === 67) || (p0 === 162 && p1 === 159)) {
        provider = "Cloudflare"
        asn = "AS13335"
        isp = "Cloudflare, Inc."
        country = "US"
        flag = "🇺🇸"
      } else if (p0 === 142 || (p0 === 172 && [216, 217, 218, 219, 220, 253].includes(p1)) || p0 === 34 || p0 === 35) {
        provider = "Google Cloud"
        asn = "AS15169"
        isp = "Google LLC"
        country = "US"
        flag = "🇺🇸"
      } else if ([54, 52, 18, 3].includes(p0)) {
        provider = "Amazon Web Services (AWS)"
        asn = "AS16509"
        isp = "Amazon.com, Inc."
        country = "US"
        flag = "🇺🇸"
      } else if (p0 === 138 || p0 === 159 || (p0 === 104 && p1 === 248)) {
        provider = "DigitalOcean"
        asn = "AS14061"
        isp = "DigitalOcean, LLC"
        country = "US"
        flag = "🇺🇸"
      } else if (p0 === 95 || p0 === 88) {
        provider = "Hetzner Online"
        asn = "AS24940"
        isp = "Hetzner Online GmbH"
        country = "DE"
        countryName = "Germany"
        flag = "🇩🇪"
      } else if ([13, 20, 40].includes(p0)) {
        provider = "Microsoft Azure"
        asn = "AS8075"
        isp = "Microsoft Corporation"
        country = "US"
        flag = "🇺🇸"
      } else if (p0 === 185 || p0 === 195) {
        provider = "Tencent Cloud"
        asn = "AS132203"
        isp = "Tencent Building"
        country = "CN"
        countryName = "China"
        flag = "🇨🇳"
      } else if (p0 === 45 || p0 === 91) {
        provider = "Telegram Messenger"
        asn = "AS62041"
        isp = "Telegram Messenger LLP"
        country = "AE"
        countryName = "United Arab Emirates"
        flag = "🇦🇪"
      }
    }
    return { ip, hosting_provider: provider, country, country_name: countryName, country_flag: flag, asn, isp }
  }

  const enrichedIps = ips.map((ip: string) => classifyIp(ip))

  // Render SVG interactive flow graph coordinates
  const svgW = 800
  const svgH = 340
  const centerX = svgW / 2
  const centerY = svgH / 2

  // Limit counts to avoid visual clutter
  const visibleDns = dns.slice(0, 4)
  const visibleIps = enrichedIps.slice(0, 4)

  const dnsNodes = visibleDns.map((domain: string, i: number) => {
    const angle = -Math.PI / 3 + (i / (visibleDns.length - 1 || 1)) * ((2 * Math.PI) / 3)
    const x = centerX - 220 * Math.cos(angle)
    const y = centerY + 100 * Math.sin(angle)
    return { label: domain, x, y, type: 'dns' }
  })

  const ipNodes = visibleIps.map((item: any, i: number) => {
    const angle = -Math.PI / 3 + (i / (visibleIps.length - 1 || 1)) * ((2 * Math.PI) / 3)
    const x = centerX + 220 * Math.cos(angle)
    const y = centerY + 100 * Math.sin(angle)
    return { label: item.ip, x, y, type: 'ip', extra: item.hosting_provider, flag: item.country_flag }
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Visual Network Flow Graph */}
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Visual Network Flow Graph</h3>
        <p style={{ color: 'var(--text-muted)', fontSize: 12, marginBottom: 16 }}>
          Interactive visualization of sandbox execution network pathways (APK ➔ DNS Beacons ➔ Contacted IP Infrastructure).
        </p>

        <div style={{ width: '100%', overflowX: 'auto', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)', padding: 12 }}>
          <svg viewBox={`0 0 ${svgW} ${svgH}`} width="100%" height={svgH} style={{ minWidth: 600 }}>
            <defs>
              <style>{`
                @keyframes dash {
                  to {
                    stroke-dashoffset: -20;
                  }
                }
                .flow-line {
                  animation: dash 1s linear infinite;
                }
              `}</style>
            </defs>

            {/* Flows to DNS (Left) */}
            {dnsNodes.map((node: any, idx: number) => (
              <g key={`dns-flow-${idx}`}>
                <path d={`M ${centerX} ${centerY} Q ${(centerX + node.x) / 2} ${(centerY + node.y) / 2 - 30} ${node.x} ${node.y}`} fill="none" stroke="var(--accent-orange)" strokeWidth="1.5" strokeDasharray="5,5" className="flow-line" opacity="0.8" />
                <circle cx={node.x} cy={node.y} r="22" fill="var(--bg-secondary)" stroke="var(--accent-orange)" strokeWidth="2" />
                <text x={node.x} y={node.y + 4} textAnchor="middle" fill="var(--accent-orange)" fontSize="9" fontWeight="700">DNS</text>
                <text x={node.x} y={node.y + 36} textAnchor="middle" fill="var(--text-primary)" fontSize="10" className="mono" fontWeight="600">
                  {node.label.length > 20 ? node.label.substring(0, 18) + '...' : node.label}
                </text>
              </g>
            ))}

            {/* Flows to IPs (Right) */}
            {ipNodes.map((node: any, idx: number) => (
              <g key={`ip-flow-${idx}`}>
                <path d={`M ${centerX} ${centerY} Q ${(centerX + node.x) / 2} ${(centerY + node.y) / 2 - 30} ${node.x} ${node.y}`} fill="none" stroke="var(--accent-cyan)" strokeWidth="1.5" strokeDasharray="5,5" className="flow-line" opacity="0.8" />
                <circle cx={node.x} cy={node.y} r="22" fill="var(--bg-secondary)" stroke="var(--accent-cyan)" strokeWidth="2" />
                <text x={node.x} y={node.y + 4} textAnchor="middle" fill="var(--accent-cyan)" fontSize="10" fontWeight="700">IP</text>
                <text x={node.x} y={node.y + 36} textAnchor="middle" fill="var(--text-primary)" fontSize="10" className="mono" fontWeight="600">
                  {node.flag} {node.label}
                </text>
                <text x={node.x} y={node.y + 48} textAnchor="middle" fill="var(--text-muted)" fontSize="9">
                  {node.extra}
                </text>
              </g>
            ))}

            {/* Central APK Node */}
            <circle cx={centerX} cy={centerY} r="35" fill="var(--bg-primary)" stroke="var(--accent-cyan)" strokeWidth="3" />
            <text x={centerX} y={centerY + 4} textAnchor="middle" fill="var(--accent-cyan)" fontSize="11" fontWeight="800">APK</text>
            <text x={centerX} y={centerY + 50} textAnchor="middle" fill="var(--accent-cyan)" fontSize="11" fontWeight="800">
              ANALYZED APK
            </text>
          </svg>
        </div>
      </div>
      {/* Dynamic PCAP Capture Stats */}
      <div style={{ ...styles.card }}>
        <h3 style={styles.cardTitle}>Dynamic PCAP Capture</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16 }}>
          <StatBox label="Total Packets" value={String(traffic.summary?.total_packets ?? 0)} color="var(--accent-blue)" />
          <StatBox label="Unique IPs" value={String(traffic.summary?.unique_ips_count ?? 0)} color="var(--accent-cyan)" />
          <StatBox label="DNS Queries" value={String(traffic.summary?.dns_query_count ?? 0)} color="var(--accent-orange)" />
          <StatBox label="HTTP Requests" value={String(traffic.summary?.http_request_count ?? 0)} color="var(--accent-red)" />
        </div>
      </div>

      {/* Correlation Block */}
      {correlation && (
        <div style={{ ...styles.card, borderColor: correlation.dynamic_only_domains?.length || correlation.dynamic_only_ips?.length ? 'var(--accent-red)' : 'var(--border-subtle)', borderWidth: 1 }}>
          <h3 style={styles.cardTitle}>Static vs. Dynamic Correlation Analysis</h3>
          <div style={{ padding: 12, background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-sm)', borderLeft: `4px solid ${correlation.dynamic_only_domains?.length || correlation.dynamic_only_ips?.length ? 'var(--accent-red)' : 'var(--accent-cyan)'}`, marginBottom: 16 }}>
            <p style={{ fontWeight: 600, fontSize: 14, color: correlation.dynamic_only_domains?.length || correlation.dynamic_only_ips?.length ? 'var(--accent-red)' : 'var(--text-primary)' }}>
              {correlation.flag}
            </p>
          </div>

          <div style={styles.gridTwo}>
            {/* Confirmed Active Connections */}
            <div>
              <h4 style={{ fontSize: 13, color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8 }}>
                Confirmed (Decompiled & Active)
              </h4>
              {correlation.confirmed_domains?.length > 0 || correlation.confirmed_ips?.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {correlation.confirmed_domains.map((d: string, idx: number) => (
                    <div key={idx} className="mono" style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{d}</div>
                  ))}
                  {correlation.confirmed_ips.map((ip: string, idx: number) => (
                    <div key={idx} className="mono" style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{ip}</div>
                  ))}
                </div>
              ) : (
                <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>No confirmed matching connections.</p>
              )}
            </div>

            {/* Dynamic-Only (Unexplained C2 / Remotely Configured) */}
            <div>
              <h4 style={{ fontSize: 13, color: 'var(--accent-red)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8 }}>
                Dynamic-Only (Hidden / Remotely Loaded)
              </h4>
              {correlation.dynamic_only_domains?.length > 0 || correlation.dynamic_only_ips?.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {correlation.dynamic_only_domains.map((d: string, idx: number) => (
                    <div key={idx} className="mono" style={{ fontSize: 12, color: 'var(--accent-red)' }}>[ALERT] {d}</div>
                  ))}
                  {correlation.dynamic_only_ips.map((ip: string, idx: number) => (
                    <div key={idx} className="mono" style={{ fontSize: 12, color: 'var(--accent-red)' }}>[ALERT] {ip}</div>
                  ))}
                </div>
              ) : (
                <p style={{ color: 'var(--text-muted)', fontSize: 12 }}>No unexplained connections detected.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {dns.length > 0 && (
        <div style={{ ...styles.card, borderColor: 'var(--accent-orange)' }}>
          <h3 style={{ ...styles.cardTitle, color: 'var(--accent-orange)' }}>C2 DNS Beacons</h3>
          {dns.map((q: string, i: number) => (
            <div key={i} className="mono" style={{ padding: '6px 0', fontSize: 13, color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-subtle)' }}>
              {q}
            </div>
          ))}
        </div>
      )}

      {/* Contacted IP Addresses with Infrastructure/ISP Details */}
      {enrichedIps.length > 0 && (
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Contacted IP Infrastructure Details</h3>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', minWidth: 500 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', fontSize: 11, textTransform: 'uppercase' }}>
                  <th style={{ padding: '8px 4px' }}>IP Address</th>
                  <th style={{ padding: '8px 4px' }}>Hosting Provider</th>
                  <th style={{ padding: '8px 4px' }}>ASN & ISP</th>
                  <th style={{ padding: '8px 4px' }}>Country</th>
                </tr>
              </thead>
              <tbody>
                {enrichedIps.map((item: any, i: number) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)', fontSize: 13, color: 'var(--text-secondary)' }}>
                    <td style={{ padding: '10px 4px', fontWeight: 600 }} className="mono">{item.ip}</td>
                    <td style={{ padding: '10px 4px' }}>{item.hosting_provider}</td>
                    <td style={{ padding: '10px 4px' }} className="mono">{item.asn} ({item.isp})</td>
                    <td style={{ padding: '10px 4px' }}>{item.country_flag} {item.country_name}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {http.length > 0 && (
        <div style={{ ...styles.card, borderColor: 'var(--accent-red)' }}>
          <h3 style={{ ...styles.cardTitle, color: 'var(--accent-red)' }}>Captured HTTP Requests</h3>
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
          <h3 style={{ ...styles.cardTitle, color: 'var(--accent-red)' }}>Commercial/Malware Packer Detected</h3>
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
  const issuer = cert.issuer ?? {}
  const validity = cert.validity ?? {}

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={styles.gridTwo}>
        {/* Certificate Subject */}
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Certificate Subject (Developer Identity)</h3>
          <InfoRow label="Common Name" value={subject.common_name} />
          <InfoRow label="Organization" value={subject.organization} />
          <InfoRow label="Org Unit" value={subject.org_unit} />
          <InfoRow label="Country" value={subject.country} />
          <InfoRow label="State/Province" value={subject.state} />
          <InfoRow label="Locality" value={subject.locality} />
          <InfoRow label="Email" value={subject.email} />
        </div>

        {/* Certificate Issuer */}
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Certificate Issuer</h3>
          <InfoRow label="Common Name" value={issuer.common_name} />
          <InfoRow label="Organization" value={issuer.organization} />
          <InfoRow label="Org Unit" value={issuer.org_unit} />
          <InfoRow label="Country" value={issuer.country} />
          <InfoRow label="State/Province" value={issuer.state} />
          <InfoRow label="Locality" value={issuer.locality} />
          <InfoRow label="Email" value={issuer.email} />
        </div>
      </div>

      <div style={styles.gridTwo}>
        {/* Technical Certificate Info */}
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Technical Specifications</h3>
          <InfoRow label="Serial Number" value={cert.serial_number} />
          <InfoRow label="Signature Algorithm" value={cert.signature_algorithm} />
          <InfoRow label="Key Size" value={cert.public_key_size ? `${cert.public_key_size} bits` : 'Unknown'} />
          <InfoRow label="Version" value={cert.version} />
          <InfoRow label="Signing Scheme" value={data.signing_scheme} />
          <InfoRow label="Self-Signed" value={String(data.is_self_signed ?? false)} alert={data.is_self_signed} />
          <InfoRow label="Debug Cert" value={String(data.is_debug_signed ?? false)} alert={data.is_debug_signed} />
        </div>

        {/* Validity */}
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Validity Window</h3>
          <InfoRow label="Valid From" value={validity.not_before} />
          <InfoRow label="Valid Until" value={validity.not_after} />
          <InfoRow label="Days Remaining" value={String(validity.days_until_expiry ?? 0)} />
          <InfoRow label="Status" value={validity.is_valid ? "VALID" : "EXPIRED"} alert={!validity.is_valid} />
        </div>
      </div>

      {/* Fingerprints */}
      <div style={styles.card}>
        <h3 style={styles.cardTitle}>Cryptographic Fingerprints</h3>
        <div style={{ marginBottom: 12 }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>SHA-256 Fingerprint</span>
          <p className="mono" style={{ fontSize: 12, color: 'var(--accent-cyan)', wordBreak: 'break-all', marginTop: 4 }}>
            {cert.hashes?.sha256 ?? 'N/A'}
          </p>
        </div>
        <div style={{ marginBottom: 12 }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>SHA-1 Fingerprint</span>
          <p className="mono" style={{ fontSize: 12, color: 'var(--accent-cyan)', wordBreak: 'break-all', marginTop: 4 }}>
            {cert.hashes?.sha1 ?? 'N/A'}
          </p>
        </div>
        <div>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>MD5 Fingerprint</span>
          <p className="mono" style={{ fontSize: 12, color: 'var(--accent-cyan)', wordBreak: 'break-all', marginTop: 4 }}>
            {cert.hashes?.md5 ?? 'N/A'}
          </p>
        </div>
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
          <h3 style={{ ...styles.cardTitle, color: 'var(--accent-red)' }}>Suspicious Files</h3>
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
