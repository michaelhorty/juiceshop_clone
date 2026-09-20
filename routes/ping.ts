/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { runPing } from '../lib/runPing'

function getErrorMessage (err: unknown): string {
  if (err && typeof err === 'object' && typeof (err as { message?: unknown }).message === 'string') {
    return (err as { message: string }).message.slice(0, 200)
  }
  return 'Unexpected error'
}

module.exports = function ping () {
  return async (req: Request, res: Response) => {
    const raw = typeof req.body?.ip === 'string'
      ? req.body.ip
      : (typeof req.query.ip === 'string' ? req.query.ip : '')
    const ip = raw.trim()

    if (!ip) {
      res.status(400).json({ error: 'Missing ip parameter' })
      return
    }

    try {
      const result = await runPing(ip)
      res.json({
        ip,
        exitCode: result.code,
        output: result.stdout || result.stderr
      })
    } catch (err) {
      const message = getErrorMessage(err)
      if (message === 'Invalid IP address') {
        res.status(400).json({ error: 'Invalid IP address' })
        return
      }
      res.status(500).json({ error: 'Ping failed' })
    }
  }
}
