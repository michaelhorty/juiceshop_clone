/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { execFile } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

export async function runDig (hostname: string): Promise<{ stdout: string, stderr: string, code: number }> {
  const ALLOWED_COMMANDS = ['dig']
  const command = 'dig'
  if (!ALLOWED_COMMANDS.includes(command)) {
    throw new Error('Command not allowed')
  }

  const term = String(hostname ?? '').replace(/[^a-zA-Z0-9._-]/g, '')
  if (!term) {
    throw new Error('Invalid hostname')
  }

  // OX Agent: Command Injection prevented by spawn with argument arrays and explicit allowlist validation
  try {
    const { stdout, stderr } = await execFileAsync(command, [term], {
      timeout: 15000,
      maxBuffer: 1024 * 1024,
      windowsHide: true
    })
    return { stdout, stderr, code: 0 }
  } catch (err: any) {
    if (typeof err.stdout === 'string' || typeof err.stderr === 'string') {
      return {
        stdout: err.stdout ?? '',
        stderr: err.stderr ?? '',
        code: typeof err.code === 'number' ? err.code : 1
      }
    }
    throw err
  }
}
