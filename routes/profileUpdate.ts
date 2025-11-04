/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')
import * as utils from '../lib/utils'

const security = require('../lib/insecurity')
const cache = require('../data/datacache')
const challenges = cache.challenges

module.exports = function updateProfile () {
  return (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (loggedInUser) {
      UserModel.findByPk(loggedInUser.data.id).then((user: UserModel | null) => {
        if (user != null) {
          const updateData: any = {}
          
          // Update username if provided
          if (req.body.username !== undefined) {
            updateData.username = req.body.username
          }
          
          // Update email if provided
          if (req.body.email !== undefined) {
            updateData.email = req.body.email
          }
          
          // Update bio if provided
          if (req.body.bio !== undefined) {
            updateData.bio = req.body.bio
          }

          void user.update(updateData).then((savedUser: UserModel) => {
            // @ts-expect-error FIXME some properties missing in savedUser
            savedUser = utils.queryResultToJson(savedUser)
            const updatedToken = security.authorize(savedUser)
            security.authenticatedUsers.put(updatedToken, savedUser)
            res.cookie('token', updatedToken)
            res.json({ 
              status: 'success', 
              user: {
                id: savedUser.data.id,
                username: savedUser.data.username,
                email: savedUser.data.email,
                bio: savedUser.data.bio,
                profileImage: savedUser.data.profileImage
              }
            })
          }).catch((error: Error) => {
            res.status(500).json({ status: 'error', message: error.message })
          })
        } else {
          res.status(404).json({ status: 'error', message: 'User not found' })
        }
      }).catch((error: Error) => {
        next(error)
      })
    } else {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
    }
  }
}
