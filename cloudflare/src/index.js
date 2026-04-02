import { handleSubmit }                                    from './handlers/submit.js'
import { handleSubmissions, handleStats, handleReport, handleDeleteSubmission } from './handlers/api.js'
import { handleDashboard }                                 from './handlers/dashboard.js'

export default {
  async fetch(request, env, ctx) {
    const url  = new URL(request.url)
    const path = url.pathname
    const method = request.method

    if (path === '/ratcatcher/submit') {
      if (method !== 'POST') return new Response('Method Not Allowed', { status: 405 })
      return handleSubmit(request, env)
    }

    const deleteMatch = path.match(/^\/ratcatcher\/api\/submissions\/([^/]+)$/)
    if (deleteMatch && method === 'DELETE') {
      return handleDeleteSubmission(request, env, deleteMatch[1])
    }

    if (method !== 'GET') return new Response('Method Not Allowed', { status: 405 })

    if (path === '/ratcatcher/dashboard')        return handleDashboard(request, env)
    if (path === '/ratcatcher/api/submissions')  return handleSubmissions(request, env)
    if (path === '/ratcatcher/api/stats')        return handleStats(request, env)

    const reportMatch = path.match(/^\/ratcatcher\/api\/report\/([^/]+)\/(brief|full)$/)
    if (reportMatch) return handleReport(request, env, reportMatch[1], reportMatch[2])

    return new Response('Not Found', { status: 404 })
  }
}
