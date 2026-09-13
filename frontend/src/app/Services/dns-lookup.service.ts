/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Injectable } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { environment } from '../../environments/environment'
import { catchError, map } from 'rxjs/operators'
import { type Observable } from 'rxjs'

export interface DnsLookupResponse {
  hostname: string
  exitCode: number
  output: string
}

export interface ReverseDnsLookupResponse {
  ip: string
  hostname: string | null
  exitCode: number
  output: string
}

@Injectable({
  providedIn: 'root'
})
export class DnsLookupService {
  private readonly hostServer = environment.hostServer
  private readonly host = this.hostServer + '/rest/dns-lookup'
  private readonly reverseHost = this.hostServer + '/rest/reverse-dns-lookup'

  constructor (private readonly http: HttpClient) { }

  lookup (hostname: string): Observable<DnsLookupResponse> {
    return this.http.post<DnsLookupResponse>(this.host, { hostname }).pipe(
      map((response: DnsLookupResponse) => response),
      catchError((error) => { throw error })
    )
  }

  reverseLookup (ip: string): Observable<ReverseDnsLookupResponse> {
    return this.http.post<ReverseDnsLookupResponse>(this.reverseHost, { ip }).pipe(
      map((response: ReverseDnsLookupResponse) => response),
      catchError((error) => { throw error })
    )
  }
}
