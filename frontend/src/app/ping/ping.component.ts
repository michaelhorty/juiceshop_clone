/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component } from '@angular/core'
import { UntypedFormControl, Validators } from '@angular/forms'
import { PingService } from '../Services/ping.service'

@Component({
  selector: 'app-ping',
  templateUrl: './ping.component.html',
  styleUrls: ['./ping.component.scss']
})
export class PingComponent {
  public ipControl: UntypedFormControl = new UntypedFormControl('', [Validators.required])
  public loading = false
  public output = ''
  public error = ''
  public lastIp = ''

  constructor (private readonly pingService: PingService) { }

  runPing () {
    this.error = ''
    this.output = ''
    const ip = String(this.ipControl.value ?? '').trim()
    if (!ip || this.ipControl.invalid) {
      this.ipControl.markAsTouched()
      return
    }

    this.loading = true
    this.lastIp = ip
    this.pingService.ping(ip).subscribe({
      next: (res) => {
        this.loading = false
        this.output = res.output || '(no output)'
      },
      error: (err) => {
        this.loading = false
        this.error = err?.error?.error || 'Ping failed'
      }
    })
  }
}
