import { describe, it, expect, vi, beforeEach } from 'vitest'
import { handleSubmit } from '../src/handlers/submit.js'

function makeEnv(overrides = {}) {
  return {
    SUBMIT_PASSWORD: 'correct-pass',
    DB: {
      prepare: vi.fn(() => ({
        bind: vi.fn(() => ({
          run: vi.fn().mockResolvedValue({ success: true })
        }))
      }))
    },
    BUCKET: {
      put: vi.fn().mockResolvedValue(undefined)
    },
    ...overrides
  }
}

function makeForm(fields = {}, files = {}) {
  const fd = new FormData()
  const defaults = {
    password:         'correct-pass',
    hostname:         'DESKTOP-ABC',
    username:         'jsmith',
    scan_timestamp:   '2026-04-01T14:32:00Z',
    verdict:          'CLEAN',
    duration:         '47.3s',
    projects_scanned: '5',
    vulnerable_count: '0',
    critical_count:   '0',
    paths_scanned:    '["C:\\\\Users\\\\jsmith\\\\dev"]',
  }
  Object.entries({ ...defaults, ...fields }).forEach(([k, v]) => fd.append(k, v))
  const briefBlob  = files.brief  ?? new Blob(['<html>brief</html>'],  { type: 'text/html' })
  const reportBlob = files.report ?? new Blob(['<html>report</html>'], { type: 'text/html' })
  fd.append('brief',  briefBlob,  'brief.html')
  fd.append('report', reportBlob, 'report.html')
  return fd
}

function makeRequest(formData, { quotedBoundary = false } = {}) {
  const req = new Request('https://mbfromit.com/ratcatcher/submit', {
    method: 'POST',
    body: formData
  })
  if (!quotedBoundary) return req
  // Simulate PowerShell's Invoke-RestMethod which sends boundary="xxx" (quoted)
  const ct = req.headers.get('content-type') || ''
  const quotedCt = ct.replace(/boundary=([^;]+)/, 'boundary="$1"')
  const headers = new Headers(req.headers)
  headers.set('content-type', quotedCt)
  return new Request(req.url, { method: req.method, headers, body: req.body, duplex: 'half' })
}

describe('handleSubmit', () => {
  it('returns 401 when password is wrong', async () => {
    const env = makeEnv()
    const req = makeRequest(makeForm({ password: 'wrong' }))
    const res = await handleSubmit(req, env)
    expect(res.status).toBe(401)
    const body = await res.json()
    expect(body.error).toBe('Unauthorized')
  })

  it('returns 400 when a required field is missing', async () => {
    const env = makeEnv()
    const fd = makeForm()
    fd.delete('hostname')
    const req = makeRequest(fd)
    const res = await handleSubmit(req, env)
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toMatch(/hostname/)
  })

  it('returns 400 when brief file is missing', async () => {
    const env = makeEnv()
    const fd = makeForm()
    fd.delete('brief')
    const req = makeRequest(fd)
    const res = await handleSubmit(req, env)
    expect(res.status).toBe(400)
  })

  it('returns 413 when brief file exceeds 25MB', async () => {
    const env = makeEnv()
    const bigBlob = new Blob([new Uint8Array(26 * 1024 * 1024)], { type: 'text/html' })
    const req = makeRequest(makeForm({}, { brief: bigBlob }))
    const res = await handleSubmit(req, env)
    expect(res.status).toBe(413)
  })

  it('returns 201 with a UUID on valid submission', async () => {
    const env = makeEnv()
    const req = makeRequest(makeForm())
    const res = await handleSubmit(req, env)
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body.id).toMatch(/^[0-9a-f-]{36}$/)
  })

  it('accepts a quoted boundary (PowerShell Invoke-RestMethod compat)', async () => {
    const env = makeEnv()
    const req = makeRequest(makeForm(), { quotedBoundary: true })
    const res = await handleSubmit(req, env)
    expect(res.status).toBe(201)
    const body = await res.json()
    expect(body.id).toMatch(/^[0-9a-f-]{36}$/)
  })

  it('uploads brief and report to R2 before writing D1', async () => {
    const env = makeEnv()
    const callOrder = []
    env.BUCKET.put = vi.fn(() => { callOrder.push('r2'); return Promise.resolve() })
    env.DB.prepare = vi.fn(() => ({
      bind: vi.fn(() => ({
        run: vi.fn(() => { callOrder.push('d1'); return Promise.resolve({ success: true }) })
      }))
    }))
    const req = makeRequest(makeForm())
    await handleSubmit(req, env)
    expect(callOrder.indexOf('r2')).toBeLessThan(callOrder.indexOf('d1'))
  })

  it('returns 500 and does not write D1 when R2 upload fails', async () => {
    const env = makeEnv()
    env.BUCKET.put = vi.fn().mockRejectedValue(new Error('R2 down'))
    const runMock = vi.fn()
    env.DB.prepare = vi.fn(() => ({ bind: vi.fn(() => ({ run: runMock })) }))
    const req = makeRequest(makeForm())
    const res = await handleSubmit(req, env)
    expect(res.status).toBe(500)
    expect(runMock).not.toHaveBeenCalled()
  })

  it('returns 500 when D1 insert fails', async () => {
    const env = makeEnv()
    env.DB.prepare = vi.fn(() => ({
      bind: vi.fn(() => ({ run: vi.fn().mockRejectedValue(new Error('D1 down')) }))
    }))
    const req = makeRequest(makeForm())
    const res = await handleSubmit(req, env)
    expect(res.status).toBe(500)
  })

  it('stores ai_verdict when provided with a valid value', async () => {
    const env = makeEnv()
    const capturedBindArgs = []
    env.DB.prepare = vi.fn(() => ({
      bind: vi.fn((...args) => {
        capturedBindArgs.push(...args)
        return { run: vi.fn().mockResolvedValue({ success: true }) }
      })
    }))
    const req = makeRequest(makeForm({ ai_verdict: 'AI_COMPROMISE', verdict: 'COMPROMISED' }))
    const res = await handleSubmit(req, env)
    expect(res.status).toBe(201)
    expect(capturedBindArgs).toContain('AI_COMPROMISE')
  })

  it('stores null ai_verdict when field is omitted', async () => {
    const env = makeEnv()
    const capturedBindArgs = []
    env.DB.prepare = vi.fn(() => ({
      bind: vi.fn((...args) => {
        capturedBindArgs.push(...args)
        return { run: vi.fn().mockResolvedValue({ success: true }) }
      })
    }))
    const req = makeRequest(makeForm()) // no ai_verdict field
    const res = await handleSubmit(req, env)
    expect(res.status).toBe(201)
    expect(capturedBindArgs).toContain(null) // ai_verdict is null
  })
})
