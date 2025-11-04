/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

const frisby = require('frisby')
const Joi = frisby.Joi
const security = require('../../lib/insecurity')

const API_URL = 'http://localhost:3000'

describe('/rest/user/profile', () => {
  let authHeader: string

  beforeEach(() => {
    return frisby.post(API_URL + '/rest/user/login', {
      headers: { 'content-type': 'application/json' },
      body: {
        email: 'admin@' + process.env.DOMAIN || 'juice-shop.herokuapp.com',
        password: 'admin123'
      }
    })
      .expect('status', 200)
      .then(({ json }) => {
        authHeader = 'Bearer ' + security.authorize({ data: { id: json.authentication.bid } })
      })
  })

  it('GET should return user profile', () => {
    return frisby.get(API_URL + '/rest/user/profile', {
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
      }
    })
      .expect('status', 200)
      .expect('jsonTypes', {
        id: Joi.number(),
        username: Joi.string(),
        email: Joi.string(),
        bio: Joi.string().allow(''),
        profileImage: Joi.string(),
        role: Joi.string()
      })
  })

  it('POST should update user profile with valid data', () => {
    return frisby.post(API_URL + '/rest/user/profile', {
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
      },
      body: {
        username: 'testuser123',
        email: 'test@example.com',
        bio: 'This is a test bio'
      }
    })
      .expect('status', 200)
      .expect('jsonTypes', {
        success: Joi.boolean(),
        message: Joi.string(),
        user: Joi.object()
      })
      .expect('json', {
        success: true
      })
  })

  it('POST should reject invalid email format', () => {
    return frisby.post(API_URL + '/rest/user/profile', {
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
      },
      body: {
        email: 'invalid-email'
      }
    })
      .expect('status', 400)
      .expect('jsonTypes', {
        error: Joi.string(),
        details: Joi.array()
      })
  })

  it('POST should reject username with invalid characters', () => {
    return frisby.post(API_URL + '/rest/user/profile', {
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
      },
      body: {
        username: 'test@user!'
      }
    })
      .expect('status', 400)
      .expect('jsonTypes', {
        error: Joi.string(),
        details: Joi.array()
      })
  })

  it('POST should reject bio that is too long', () => {
    const longBio = 'a'.repeat(501)
    return frisby.post(API_URL + '/rest/user/profile', {
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
      },
      body: {
        bio: longBio
      }
    })
      .expect('status', 400)
      .expect('jsonTypes', {
        error: Joi.string(),
        details: Joi.array()
      })
  })

  it('POST should update password with valid current password', () => {
    return frisby.post(API_URL + '/rest/user/profile', {
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
      },
      body: {
        currentPassword: 'admin123',
        newPassword: 'NewSecurePassword123'
      }
    })
      .expect('status', 200)
      .expect('jsonTypes', {
        success: Joi.boolean(),
        message: Joi.string(),
        user: Joi.object()
      })
      .expect('json', {
        success: true
      })
  })

  it('POST should reject password change without current password', () => {
    return frisby.post(API_URL + '/rest/user/profile', {
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
      },
      body: {
        newPassword: 'NewSecurePassword123'
      }
    })
      .expect('status', 400)
      .expect('jsonTypes', {
        error: Joi.string()
      })
  })

  it('POST should reject password change with incorrect current password', () => {
    return frisby.post(API_URL + '/rest/user/profile', {
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
      },
      body: {
        currentPassword: 'wrongpassword',
        newPassword: 'NewSecurePassword123'
      }
    })
      .expect('status', 400)
      .expect('jsonTypes', {
        error: Joi.string()
      })
  })

  it('POST should reject weak new password', () => {
    return frisby.post(API_URL + '/rest/user/profile', {
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json'
      },
      body: {
        currentPassword: 'admin123',
        newPassword: 'weak'
      }
    })
      .expect('status', 400)
      .expect('jsonTypes', {
        error: Joi.string(),
        details: Joi.array()
      })
  })

  it('POST should require authentication', () => {
    return frisby.post(API_URL + '/rest/user/profile', {
      headers: {
        'Content-Type': 'application/json'
      },
      body: {
        username: 'testuser'
      }
    })
      .expect('status', 500)
  })
})
