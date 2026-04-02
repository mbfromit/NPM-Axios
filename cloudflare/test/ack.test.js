import { describe, it, expect, vi } from 'vitest'
import { handleGetAcks, handlePostAck } from '../src/handlers/ack.js'

const ADMIN_PW = 'test-pw'

function makeEnv(dbRows = [], insertError = null) {
  return {
    ADMIN_PASSWORD: ADMIN_PW,
    DB: {
      prepare: vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          all:  vi.fn().mockResolvedValue({ results: dbRows }),
          run:  insertError
            ? vi.fn().mockRejectedValue(insertError)
            : vi.fn().mockResolvedValue({}),
          first: vi.fn().mockResolvedValue(dbRows[0] ?? null),
        }),
      }),
    },
  }
}

function makeReq(method, pw = ADMIN_PW, body = null) {
  const headers = new Headers({ 'X-Admin-Password': pw })
  if (body) headers.set('Content-Type', 'application/json')
  return new Request('https://example.com/', {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  })
}

describe('handleGetAcks', () => {
  it('returns 401 with wrong password', async () => {
    const r = await handleGetAcks(makeReq('GET', 'wrong'), makeEnv(), 'sub1')
    expect(r.status).toBe(401)
  })

  it('returns acks array for submission', async () => {
    const rows = [
      { finding_hash: 'abc123', reason: 'Test tool', acknowledged_at: '2026-04-02T10:00:00Z' },
    ]
    const r = await handleGetAcks(makeReq('GET'), makeEnv(rows), 'sub1')
    expect(r.status).toBe(200)
    const body = await r.json()
    expect(body.acks).toHaveLength(1)
    expect(body.acks[0].finding_hash).toBe('abc123')
  })

  it('returns empty array when no acks', async () => {
    const r = await handleGetAcks(makeReq('GET'), makeEnv([]), 'sub1')
    const body = await r.json()
    expect(body.acks).toHaveLength(0)
  })
})

describe('handlePostAck', () => {
  it('returns 401 with wrong password', async () => {
    const r = await handlePostAck(makeReq('POST', 'wrong', {}), makeEnv(), 'sub1')
    expect(r.status).toBe(401)
  })

  it('returns 400 when finding_hash missing', async () => {
    const r = await handlePostAck(makeReq('POST', ADMIN_PW, { reason: 'ok' }), makeEnv(), 'sub1')
    expect(r.status).toBe(400)
  })

  it('returns 400 when reason missing', async () => {
    const r = await handlePostAck(makeReq('POST', ADMIN_PW, { finding_hash: 'abc' }), makeEnv(), 'sub1')
    expect(r.status).toBe(400)
  })

  it('returns 400 when reason is blank', async () => {
    const r = await handlePostAck(makeReq('POST', ADMIN_PW, { finding_hash: 'abc', reason: '   ' }), makeEnv(), 'sub1')
    expect(r.status).toBe(400)
  })

  it('saves ack and returns 201', async () => {
    const r = await handlePostAck(
      makeReq('POST', ADMIN_PW, { finding_hash: 'abc123', reason: 'Dev tooling, not RAT' }),
      makeEnv(),
      'sub1'
    )
    expect(r.status).toBe(201)
    const body = await r.json()
    expect(body.ok).toBe(true)
  })

  it('returns 200 on duplicate ack (updates existing)', async () => {
    const dupErr = new Error('UNIQUE constraint failed')
    let callCount = 0
    const env = {
      ADMIN_PASSWORD: ADMIN_PW,
      DB: {
        prepare: vi.fn().mockReturnValue({
          bind: vi.fn().mockReturnValue({
            run: vi.fn().mockImplementation(() => {
              callCount++
              if (callCount === 1) return Promise.reject(dupErr)
              return Promise.resolve({})
            }),
          }),
        }),
      },
    }
    const r = await handlePostAck(
      makeReq('POST', ADMIN_PW, { finding_hash: 'abc123', reason: 'updated reason' }),
      env,
      'sub1'
    )
    expect(r.status).toBe(200)
    const body = await r.json()
    expect(body.ok).toBe(true)
    expect(body.updated).toBe(true)
  })
})
