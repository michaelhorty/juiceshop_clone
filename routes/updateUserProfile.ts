/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')
import * as utils from '../lib/utils'
import multer from 'multer'
import path from 'path'
import fs from 'fs'
import crypto from 'crypto'

const security = require('../lib/insecurity')
const cache = require('../data/datacache')
const challenges = cache.challenges

// Configure multer for secure file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/profile-images/'
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true })
    }
    cb(null, uploadDir)
  },
  filename: (req, file, cb) => {
    // Generate secure filename with timestamp and random string
    const uniqueSuffix = Date.now() + '-' + crypto.randomBytes(16).toString('hex')
    const sanitizedOriginalName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '')
    cb(null, `profile-${uniqueSuffix}-${sanitizedOriginalName}`)
  }
})

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 1
  },
  fileFilter: (req, file, cb) => {
    // Only allow image files
    const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true)
    } else {
      cb(new Error('Only image files are allowed'))
    }
  }
})

// Input validation and sanitization
const validateInput = (data: any) => {
  const errors: string[] = []
  
  if (data.username !== undefined) {
    if (typeof data.username !== 'string' || data.username.length < 3 || data.username.length > 30) {
      errors.push('Username must be between 3 and 30 characters')
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(data.username)) {
      errors.push('Username can only contain letters, numbers, underscores, and hyphens')
    }
  }
  
  if (data.email !== undefined) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(data.email)) {
      errors.push('Invalid email format')
    }
    if (data.email.length > 254) {
      errors.push('Email is too long')
    }
  }
  
  if (data.bio !== undefined) {
    if (typeof data.bio !== 'string' || data.bio.length > 500) {
      errors.push('Bio must be less than 500 characters')
    }
  }
  
  if (data.currentPassword !== undefined && typeof data.currentPassword !== 'string') {
    errors.push('Current password is required for password changes')
  }
  
  if (data.newPassword !== undefined) {
    if (typeof data.newPassword !== 'string' || data.newPassword.length < 8) {
      errors.push('New password must be at least 8 characters long')
    }
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(data.newPassword)) {
      errors.push('New password must contain at least one uppercase letter, one lowercase letter, and one number')
    }
  }
  
  return errors
}

// Secure password hashing using bcrypt (fallback to crypto for compatibility)
const hashPassword = (password: string): string => {
  try {
    // Try to use bcrypt if available
    const bcrypt = require('bcrypt')
    return bcrypt.hashSync(password, 12)
  } catch (error) {
    // Fallback to crypto with salt
    const salt = crypto.randomBytes(16).toString('hex')
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex')
    return `${salt}:${hash}`
  }
}

// Verify password
const verifyPassword = (password: string, hashedPassword: string): boolean => {
  try {
    // Try to use bcrypt if available
    const bcrypt = require('bcrypt')
    return bcrypt.compareSync(password, hashedPassword)
  } catch (error) {
    // Fallback to crypto verification
    if (hashedPassword.includes(':')) {
      const [salt, hash] = hashedPassword.split(':')
      const testHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex')
      return hash === testHash
    }
    // Legacy MD5 fallback (insecure but for compatibility)
    return security.hash(password) === hashedPassword
  }
}

module.exports = function updateUserProfile () {
  return (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (loggedInUser) {
      UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => {
        if (user != null) {
          try {
            // Validate input
            const validationErrors = validateInput(req.body)
            if (validationErrors.length > 0) {
              return res.status(400).json({
                error: 'Validation failed',
                details: validationErrors
              })
            }

            challengeUtils.solveIf(challenges.csrfChallenge, () => {
              return ((req.headers.origin?.includes('://htmledit.squarefree.com')) ??
                (req.headers.referer?.includes('://htmledit.squarefree.com'))) &&
                req.body.username !== user.username
            })

            const updateData: any = {}
            
            // Update username
            if (req.body.username !== undefined) {
              updateData.username = security.sanitizeSecure(req.body.username)
            }
            
            // Update email
            if (req.body.email !== undefined) {
              updateData.email = security.sanitizeSecure(req.body.email)
            }
            
            // Update bio
            if (req.body.bio !== undefined) {
              updateData.bio = security.sanitizeSecure(req.body.bio)
            }
            
            // Handle password change
            if (req.body.newPassword !== undefined) {
              if (!req.body.currentPassword) {
                return res.status(400).json({
                  error: 'Current password is required to change password'
                })
              }
              
              // Verify current password
              if (!verifyPassword(req.body.currentPassword, user.password)) {
                return res.status(400).json({
                  error: 'Current password is incorrect'
                })
              }
              
              // Hash new password securely
              updateData.password = hashPassword(req.body.newPassword)
            }

            // Handle profile image upload
            if (req.file) {
              // Delete old profile image if it exists and is not default
              if (user.profileImage && 
                  user.profileImage !== '/assets/public/images/uploads/default.svg' &&
                  user.profileImage !== '/assets/public/images/uploads/defaultAdmin.png') {
                const oldImagePath = path.join(process.cwd(), 'frontend/dist', user.profileImage)
                if (fs.existsSync(oldImagePath)) {
                  fs.unlinkSync(oldImagePath)
                }
              }
              
              // Set new profile image path
              updateData.profileImage = `/assets/public/images/uploads/${req.file.filename}`
            }

            // Update user with parameterized query (handled by Sequelize)
            const savedUser = await user.update(updateData)
            
            // Convert to JSON and update session
            const userJson = utils.queryResultToJson(savedUser)
            const updatedToken = security.authorize(userJson)
            security.authenticatedUsers.put(updatedToken, userJson)
            res.cookie('token', updatedToken, {
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production',
              sameSite: 'strict'
            })

            // Return success response
            res.json({
              success: true,
              message: 'Profile updated successfully',
              user: {
                id: userJson.id,
                username: userJson.username,
                email: userJson.email,
                bio: userJson.bio,
                profileImage: userJson.profileImage,
                role: userJson.role
              }
            })

          } catch (error) {
            console.error('Profile update error:', error)
            res.status(500).json({
              error: 'Failed to update profile',
              message: 'An error occurred while updating your profile'
            })
          }
        } else {
          res.status(404).json({
            error: 'User not found'
          })
        }
      }).catch((error: Error) => {
        console.error('Database error:', error)
        next(error)
      })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}

// Export the upload middleware for use in routes
module.exports.upload = upload
