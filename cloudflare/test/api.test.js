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
})
