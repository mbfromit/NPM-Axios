import { describe, it, expect, vi } from 'vitest'

// Mock handler modules before importing the worker
vi.mock('../src/handlers/submit.js', () => ({
  handleSubmit: vi.fn().mockResolvedValue(new Response('submit', { status: 201 }))
}))
vi.mock('../src/handlers/api.js', () => ({
  handleSubmissions:      vi.fn().mockResolvedValue(new Response('subs', { status: 200 })),
  handleStats:            vi.fn().mockResolvedValue(new Response('stats', { status: 200 })),
  handleReport:           vi.fn().mockResolvedValue(new Response('report', { status: 200 })),
  handleDeleteSubmission: vi.fn().mockResolvedValue(new Response('deleted', { status: 200 }))
}))
vi.mock('../src/handlers/dashboard.js', () => ({
  handleDashboard: vi.fn().mockResolvedValue(new Response('dash', { status: 200 }))
}))

import worker from '../src/index.js'

const env = {}
const ctx = { waitUntil: vi.fn() }

describe('Worker router', () => {
  it('routes POST /ratcatcher/submit to handleSubmit', async () => {
    const req = new Request('https://mbfromit.com/ratcatcher/submit', { method: 'POST' })
    const res = await worker.fetch(req, env, ctx)
    expect(res.status).toBe(201)
  })

  it('routes GET /ratcatcher/dashboard to handleDashboard', async () => {
    const req = new Request('https://mbfromit.com/ratcatcher/dashboard')
    const res = await worker.fetch(req, env, ctx)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('dash')
  })

  it('routes GET /ratcatcher/api/submissions to handleSubmissions', async () => {
    const req = new Request('https://mbfromit.com/ratcatcher/api/submissions')
    const res = await worker.fetch(req, env, ctx)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('subs')
  })

  it('routes GET /ratcatcher/api/stats to handleStats', async () => {
    const req = new Request('https://mbfromit.com/ratcatcher/api/stats')
    const res = await worker.fetch(req, env, ctx)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('stats')
  })

  it('routes GET /ratcatcher/api/report/:id/brief to handleReport', async () => {
    const req = new Request('https://mbfromit.com/ratcatcher/api/report/abc-123/brief')
    const res = await worker.fetch(req, env, ctx)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('report')
  })

  it('routes GET /ratcatcher/api/report/:id/full to handleReport', async () => {
    const req = new Request('https://mbfromit.com/ratcatcher/api/report/abc-123/full')
    const res = await worker.fetch(req, env, ctx)
    expect(res.status).toBe(200)
  })

  it('returns 404 for unknown paths', async () => {
    const req = new Request('https://mbfromit.com/ratcatcher/unknown')
    const res = await worker.fetch(req, env, ctx)
    expect(res.status).toBe(404)
  })

  it('returns 405 for wrong method on submit', async () => {
    const req = new Request('https://mbfromit.com/ratcatcher/submit', { method: 'GET' })
    const res = await worker.fetch(req, env, ctx)
    expect(res.status).toBe(405)
  })

  it('routes DELETE /ratcatcher/api/submissions/:id to handleDeleteSubmission', async () => {
    const req = new Request('https://mbfromit.com/ratcatcher/api/submissions/abc-123', { method: 'DELETE' })
    const res = await worker.fetch(req, env, ctx)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('deleted')
  })
})
