import { handleSubmit }                                    from './handlers/submit.js'
import { handleSubmissions, handleStats, handleReport, handleDeleteSubmission, handleExport } from './handlers/api.js'
import { handleDashboard }                                 from './handlers/dashboard.js'
import { handleGetAcks, handlePostAck, handleUpdateFindingsCount } from './handlers/ack.js'
import { handleAiVerify, handleGetAiVerdicts, handleAiVerifyAll, handleAiStatus, handleAiWarmup } from './handlers/ai-verify.js'

export default {
  async fetch(request, env, ctx) {
    const url  = new URL(request.url)
    const path = url.pathname
    const method = request.method

    // Support both /ratcatcher/ and /ratcatcher-dev/ path prefixes
    const prefixMatch = path.match(/^\/(ratcatcher(?:-dev)?)\//)
    if (!prefixMatch) return new Response('Not Found', { status: 404 })
    const base = '/' + prefixMatch[1]
    const rel  = path.slice(base.length)  // e.g. "/submit", "/dashboard", "/api/..."

    if (rel === '/submit') {
      if (method !== 'POST') return new Response('Method Not Allowed', { status: 405 })
      return handleSubmit(request, env, ctx)
    }

    const deleteMatch = rel.match(/^\/api\/submissions\/([^/]+)$/)
    if (deleteMatch && method === 'DELETE') {
      return handleDeleteSubmission(request, env, deleteMatch[1])
    }

    const fcMatch = rel.match(/^\/api\/submissions\/([^/]+)\/findings-count$/)
    if (fcMatch && method === 'PUT') {
      return handleUpdateFindingsCount(request, env, fcMatch[1])
    }

    const ackMatch = rel.match(/^\/api\/submissions\/([^/]+)\/acks$/)
    if (ackMatch) {
      if (method === 'GET')  return handleGetAcks(request, env, ackMatch[1])
      if (method === 'POST') return handlePostAck(request, env, ackMatch[1])
      return new Response('Method Not Allowed', { status: 405 })
    }

    const aiVerifyMatch = rel.match(/^\/api\/submissions\/([^/]+)\/ai-verify$/)
    if (aiVerifyMatch && method === 'POST') {
      return handleAiVerify(request, env, aiVerifyMatch[1])
    }

    const aiVerdictsMatch = rel.match(/^\/api\/submissions\/([^/]+)\/ai-verdicts$/)
    if (aiVerdictsMatch && method === 'GET') {
      return handleGetAiVerdicts(request, env, aiVerdictsMatch[1])
    }

    if (rel === '/api/ai-verify-all' && method === 'POST') {
      return handleAiVerifyAll(request, env, ctx)
    }

    if (rel === '/api/ai-warmup' && method === 'POST') {
      return handleAiWarmup(request, env)
    }

    if (method !== 'GET') return new Response('Method Not Allowed', { status: 405 })

    if (rel === '/dashboard')        return handleDashboard(request, env)
    if (rel === '/api/submissions')  return handleSubmissions(request, env)
    if (rel === '/api/stats')        return handleStats(request, env)
    if (rel === '/api/export')       return handleExport(request, env)
    if (rel === '/api/ai-status')    return handleAiStatus(request, env)

    const reportMatch = rel.match(/^\/api\/report\/([^/]+)\/(brief|full)$/)
    if (reportMatch) return handleReport(request, env, reportMatch[1], reportMatch[2])

    return new Response('Not Found', { status: 404 })
  }
}
