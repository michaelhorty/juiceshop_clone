/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Socket, isIP } from 'net'

const PROBE_PORT = 80
const TIMEOUT_MS = 5000

export async function runPing (ipAddress: string): Promise<{ stdout: string, stderr: string, code: number }> {
  // Allowlist: strip anything that is not a valid IP character, then verify with net.isIP
  const term = String(ipAddress ?? '').replace(/[^0-9a-fA-F.:]/g, '')
  if (!term || isIP(term) === 0) {
    throw new Error('Invalid IP address')
  }

  const started = Date.now()

  return await new Promise((resolve) => {
    const socket = new Socket()
    let settled = false

    const finish = (code: number, stdout: string, stderr = '') => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve({ stdout, stderr, code })
    }

    socket.setTimeout(TIMEOUT_MS)

    socket.once('connect', () => {
      const ms = Date.now() - started
      finish(0, [
        `PING ${term} (TCP/${PROBE_PORT})`,
        `Connected to ${term}:${PROBE_PORT}: tcp_seq=1 time=${ms} ms`,
        ``,
        `--- ${term} ping statistics ---`,
        `1 packets transmitted, 1 received, 0% packet loss, time ${ms}ms`
      ].join('\n'))
    })

    socket.once('timeout', () => {
      const ms = Date.now() - started
      finish(1, '', `Request timeout for ${term}:${PROBE_PORT} after ${ms}ms`)
    })

    socket.once('error', (err) => {
      const ms = Date.now() - started
      finish(1, '', `Ping to ${term}:${PROBE_PORT} failed after ${ms}ms: ${err.message}`)
    })

    socket.connect(PROBE_PORT, term)
  })
}
