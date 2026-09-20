/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Injectable } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { environment } from '../../environments/environment'
import { catchError, map } from 'rxjs/operators'
import { type Observable } from 'rxjs'

export interface PingResponse {
  ip: string
  exitCode: number
  output: string
}

@Injectable({
  providedIn: 'root'
})
export class PingService {
  private readonly hostServer = environment.hostServer
  private readonly host = this.hostServer + '/rest/ping'

  constructor (private readonly http: HttpClient) { }

  ping (ip: string): Observable<PingResponse> {
    return this.http.post<PingResponse>(this.host, { ip }).pipe(
      map((response: PingResponse) => response),
      catchError((error) => { throw error })
    )
  }
}
