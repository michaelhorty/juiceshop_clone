/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { runDig } from '../lib/runDig'

function getErrorMessage (err: unknown): string {
  if (err && typeof err === 'object' && typeof (err as { message?: unknown }).message === 'string') {
    return (err as { message: string }).message.slice(0, 200)
  }
  return 'Unexpected error'
}

module.exports = function dnsLookup () {
  return async (req: Request, res: Response) => {
    const raw = typeof req.body?.hostname === 'string'
      ? req.body.hostname
      : (typeof req.query.hostname === 'string' ? req.query.hostname : '')
    const hostname = raw.trim()

    if (!hostname) {
      res.status(400).json({ error: 'Missing hostname parameter' })
      return
    }

    try {
      const result = await runDig(hostname)
      res.json({
        hostname,
        exitCode: result.code,
        output: result.stdout || result.stderr
      })
    } catch (err) {
      const message = getErrorMessage(err)
      if (message === 'Invalid hostname') {
        res.status(400).json({ error: 'Invalid hostname' })
        return
      }
      res.status(500).json({ error: 'DNS lookup failed' })
    }
  }
}
