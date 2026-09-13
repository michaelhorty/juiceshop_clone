/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component } from '@angular/core'
import { UntypedFormControl, Validators } from '@angular/forms'
import { DnsLookupService } from '../Services/dns-lookup.service'

@Component({
  selector: 'app-dns-lookup',
  templateUrl: './dns-lookup.component.html',
  styleUrls: ['./dns-lookup.component.scss']
})
export class DnsLookupComponent {
  public hostnameControl: UntypedFormControl = new UntypedFormControl('', [Validators.required])
  public ipControl: UntypedFormControl = new UntypedFormControl('', [Validators.required])
  public loading = false
  public reverseLoading = false
  public output = ''
  public reverseOutput = ''
  public error = ''
  public reverseError = ''
  public lastHostname = ''
  public lastIp = ''
  public reverseHostname = ''

  constructor (private readonly dnsLookupService: DnsLookupService) { }

  runLookup () {
    this.error = ''
    this.output = ''
    const hostname = String(this.hostnameControl.value ?? '').trim()
    if (!hostname || this.hostnameControl.invalid) {
      this.hostnameControl.markAsTouched()
      return
    }

    this.loading = true
    this.lastHostname = hostname
    this.dnsLookupService.lookup(hostname).subscribe({
      next: (res) => {
        this.loading = false
        this.output = res.output || '(no output)'
      },
      error: (err) => {
        this.loading = false
        this.error = err?.error?.error || 'DNS lookup failed'
      }
    })
  }

  runReverseLookup () {
    this.reverseError = ''
    this.reverseOutput = ''
    this.reverseHostname = ''
    const ip = String(this.ipControl.value ?? '').trim()
    if (!ip || this.ipControl.invalid) {
      this.ipControl.markAsTouched()
      return
    }

    this.reverseLoading = true
    this.lastIp = ip
    this.dnsLookupService.reverseLookup(ip).subscribe({
      next: (res) => {
        this.reverseLoading = false
        this.reverseHostname = res.hostname || '(no PTR record)'
        this.reverseOutput = res.output || '(no output)'
      },
      error: (err) => {
        this.reverseLoading = false
        this.reverseError = err?.error?.error || 'Reverse DNS lookup failed'
      }
    })
  }
}
