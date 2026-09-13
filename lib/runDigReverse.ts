/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { execFile } from 'child_process'
import { isIP } from 'net'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

function parsePtrHostname (output: string): string {
  const answerIdx = output.indexOf(';; ANSWER SECTION:')
  const section = answerIdx >= 0 ? output.slice(answerIdx) : output
  for (const line of section.split('\n')) {
    const match = line.match(/^\S+\s+\d+\s+IN\s+PTR\s+(\S+)/)
    if (match) {
      return match[1]
    }
  }
  return ''
}

export async function runDigReverse (ipAddress: string): Promise<{ stdout: string, stderr: string, code: number, hostname: string }> {
  const ALLOWED_COMMANDS = ['dig']
  const command = 'dig'
  if (!ALLOWED_COMMANDS.includes(command)) {
    throw new Error('Command not allowed')
  }

  const term = String(ipAddress ?? '').replace(/[^0-9a-fA-F.:]/g, '')
  if (!term || isIP(term) === 0) {
    throw new Error('Invalid IP address')
  }

  // OX Agent: Command Injection prevented by spawn with argument arrays and explicit allowlist validation
  try {
    const { stdout, stderr } = await execFileAsync(command, ['-x', term], {
      timeout: 15000,
      maxBuffer: 1024 * 1024,
      windowsHide: true
    })
    const output = stdout || stderr
    return { stdout, stderr, code: 0, hostname: parsePtrHostname(output) }
  } catch (err: any) {
    if (typeof err.stdout === 'string' || typeof err.stderr === 'string') {
      const stdout = err.stdout ?? ''
      const stderr = err.stderr ?? ''
      const output = stdout || stderr
      return {
        stdout,
        stderr,
        code: typeof err.code === 'number' ? err.code : 1,
        hostname: parsePtrHostname(output)
      }
    }
    throw err
  }
}
