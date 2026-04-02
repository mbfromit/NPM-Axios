import { describe, it, expect, vi, beforeEach } from 'vitest'
import { handleSubmissions, handleStats, handleReport } from '../src/handlers/api.js'

const ADMIN_PW = 'admin-secret'

function makeEnv(overrides = {}) {
  return {
    ADMIN_PASSWORD: ADMIN_PW,
    DB: {
      prepare: vi.fn(() => ({
        bind:  vi.fn(() => ({
          run:   vi.fn().mockResolvedValue({}),
          first: vi.fn().mockResolvedValue(null),
          all:   vi.fn().mockResolvedValue({ results: [] })
        })),
        first: vi.fn().mockResolvedValue(null),
        all:   vi.fn().mockResolvedValue({ results: [] })
      }))
    },
    BUCKET: {
      get: vi.fn().mockResolvedValue(null)
    },
    ...overrides
  }
}

function get(path, pw = ADMIN_PW) {
  return new Request('https://mbfromit.com' + path, {
    headers: pw ? { 'X-Admin-Password': pw } : {}
  })
}

// ── /api/submissions ────────────────────────────────────────────────────────

describe('handleSubmissions', () => {
  it('returns 401 without admin password', async () => {
    const res = await handleSubmissions(get('/ratcatcher/api/submissions', ''), makeEnv())
    expect(res.status).toBe(401)
  })

  it('returns 401 with wrong admin password', async () => {
    const res = await handleSubmissions(get('/ratcatcher/api/submissions', 'wrong'), makeEnv())
    expect(res.status).toBe(401)
  })

  it('returns 200 with correct structure', async () => {
    const env = makeEnv()
    env.DB.prepare = vi.fn()
      .mockReturnValueOnce({ first: vi.fn().mockResolvedValue({ total: 2 }) })
      .mockReturnValueOnce({
        bind: vi.fn(() => ({
          all: vi.fn().mockResolvedValue({
            results: [
              { id: 'a', hostname: 'H1', username: 'u1', submitted_at: '2026-04-01T12:00:00Z',
                verdict: 'CLEAN', duration: '10s', projects_scanned: 3,
                vulnerable_count: 0, critical_count: 0 }
            ]
          })
        }))
      })

    const res = await handleSubmissions(get('/ratcatcher/api/submissions?page=1&limit=50'), env)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.total).toBe(2)
    expect(body.page).toBe(1)
    expect(body.limit).toBe(50)
    expect(body.submissions).toHaveLength(1)
    expect(body.submissions[0].id).toBe('a')
  })

  it('uses page and limit query params for offset', async () => {
    const env = makeEnv()
    let capturedOffset = null
    env.DB.prepare = vi.fn()
      .mockReturnValueOnce({ first: vi.fn().mockResolvedValue({ total: 200 }) })
      .mockReturnValueOnce({
        bind: vi.fn((...args) => {
          capturedOffset = args[1]
          return { all: vi.fn().mockResolvedValue({ results: [] }) }
        })
      })
    await handleSubmissions(get('/ratcatcher/api/submissions?page=3&limit=10'), env)
    expect(capturedOffset).toBe(20)
  })

  it('defaults page to 1 when page param is non-numeric', async () => {
    const env = makeEnv()
    let capturedOffset = null
    env.DB.prepare = vi.fn()
      .mockReturnValueOnce({ first: vi.fn().mockResolvedValue({ total: 0 }) })
      .mockReturnValueOnce({
        bind: vi.fn((...args) => {
          capturedOffset = args[1]
          return { all: vi.fn().mockResolvedValue({ results: [] }) }
        })
      })
    await handleSubmissions(get('/ratcatcher/api/submissions?page=abc'), env)
    expect(capturedOffset).toBe(0) // page defaults to 1, offset = (1-1)*50 = 0
  })

  it('caps limit at 100', async () => {
    const env = makeEnv()
    let capturedLimit = null
    env.DB.prepare = vi.fn()
      .mockReturnValueOnce({ first: vi.fn().mockResolvedValue({ total: 0 }) })
      .mockReturnValueOnce({
        bind: vi.fn((...args) => {
          capturedLimit = args[0]
          return { all: vi.fn().mockResolvedValue({ results: [] }) }
        })
      })
    await handleSubmissions(get('/ratcatcher/api/submissions?limit=999'), env)
    expect(capturedLimit).toBe(100)
  })

  it('returns 500 when DB query fails', async () => {
    const env = makeEnv()
    env.DB.prepare = vi.fn(() => ({ first: vi.fn().mockRejectedValue(new Error('DB down')) }))
    const res = await handleSubmissions(get('/ratcatcher/api/submissions'), env)
    expect(res.status).toBe(500)
  })
})

// ── /api/stats ──────────────────────────────────────────────────────────────

describe('handleStats', () => {
  it('returns 401 without admin password', async () => {
    const res = await handleStats(get('/ratcatcher/api/stats', ''), makeEnv())
    expect(res.status).toBe(401)
  })

  it('returns total, clean, compromised counts', async () => {
    const env = makeEnv()
    env.DB.prepare = vi.fn(() => ({
      first: vi.fn().mockResolvedValue({ total: 100, clean: 90, compromised: 10 })
    }))
    const res = await handleStats(get('/ratcatcher/api/stats'), env)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toEqual({ total: 100, clean: 90, compromised: 10 })
  })

  it('returns zeros on empty table', async () => {
    const env = makeEnv()
    env.DB.prepare = vi.fn(() => ({
      first: vi.fn().mockResolvedValue({ total: null, clean: null, compromised: null })
    }))
    const res = await handleStats(get('/ratcatcher/api/stats'), env)
    const body = await res.json()
    expect(body).toEqual({ total: 0, clean: 0, compromised: 0 })
  })

  it('returns 500 when DB query fails', async () => {
    const env = makeEnv()
    env.DB.prepare = vi.fn(() => ({ first: vi.fn().mockRejectedValue(new Error('DB down')) }))
    const res = await handleStats(get('/ratcatcher/api/stats'), env)
    expect(res.status).toBe(500)
  })
})

// ── /api/report/:id/:type ───────────────────────────────────────────────────

describe('handleReport', () => {
  it('returns 401 without admin password', async () => {
    const res = await handleReport(get('/ratcatcher/api/report/x/brief', ''), makeEnv(), 'x', 'brief')
    expect(res.status).toBe(401)
  })

  it('returns 404 HTML when submission ID not found in DB', async () => {
    const env = makeEnv()
    env.DB.prepare = vi.fn(() => ({ bind: vi.fn(() => ({ first: vi.fn().mockResolvedValue(null) })) }))
    const res = await handleReport(get('/ratcatcher/api/report/missing/brief'), env, 'missing', 'brief')
    expect(res.status).toBe(404)
    const html = await res.text()
    expect(html).toContain('no longer available')
  })

  it('returns 404 HTML when R2 object is missing', async () => {
    const env = makeEnv()
    env.DB.prepare = vi.fn(() => ({
      bind: vi.fn(() => ({
        first: vi.fn().mockResolvedValue({ brief_key: 'submissions/x/brief.html', report_key: 'submissions/x/report.html' })
      }))
    }))
    env.BUCKET.get = vi.fn().mockResolvedValue(null)
    const res = await handleReport(get('/ratcatcher/api/report/x/brief'), env, 'x', 'brief')
    expect(res.status).toBe(404)
    const html = await res.text()
    expect(html).toContain('no longer available')
  })

  it('injects Full Report banner into brief HTML', async () => {
    const env = makeEnv()
    const briefHtml = '<html><body><h1>Brief</h1></body></html>'
    env.DB.prepare = vi.fn(() => ({
      bind: vi.fn(() => ({
        first: vi.fn().mockResolvedValue({ brief_key: 'submissions/abc/brief.html', report_key: 'submissions/abc/report.html' })
      }))
    }))
    env.BUCKET.get = vi.fn().mockResolvedValue({ text: async () => briefHtml })
    const res = await handleReport(get('/ratcatcher/api/report/abc/brief'), env, 'abc', 'brief')
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain('Full Technical Report')
    expect(html).toContain("postMessage({type:'vw',id:'abc',rtype:'full'}")
    expect(html).toContain('<h1>Brief</h1>')
  })

  it('serves full report HTML without banner injection', async () => {
    const env = makeEnv()
    const reportHtml = '<html><body><h1>Full Report</h1></body></html>'
    env.DB.prepare = vi.fn(() => ({
      bind: vi.fn(() => ({
        first: vi.fn().mockResolvedValue({ brief_key: 'submissions/abc/brief.html', report_key: 'submissions/abc/report.html' })
      }))
    }))
    env.BUCKET.get = vi.fn().mockResolvedValue({ text: async () => reportHtml })
    const res = await handleReport(get('/ratcatcher/api/report/abc/full'), env, 'abc', 'full')
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain('<h1>Full Report</h1>')
    expect(html).not.toContain('Full Technical Report')
  })

  it('fetches brief_key for brief type and report_key for full type', async () => {
    const env = makeEnv()
    let capturedKey = null
    env.DB.prepare = vi.fn(() => ({
      bind: vi.fn(() => ({
        first: vi.fn().mockResolvedValue({ brief_key: 'submissions/abc/brief.html', report_key: 'submissions/abc/report.html' })
      }))
    }))
    env.BUCKET.get = vi.fn(key => { capturedKey = key; return Promise.resolve({ text: async () => '<body></body>' }) })
    await handleReport(get('/ratcatcher/api/report/abc/full'), env, 'abc', 'full')
    expect(capturedKey).toBe('submissions/abc/report.html')
  })
})
