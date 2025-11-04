/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, OnInit } from '@angular/core'
import { FormBuilder, FormGroup, Validators } from '@angular/forms'
import { HttpClient, HttpHeaders } from '@angular/common/http'
import { MatSnackBar } from '@angular/material/snack-bar'
import { DomSanitizer, SafeUrl } from '@angular/platform-browser'

interface User {
  id: number
  username: string
  email: string
  bio: string
  profileImage: string
  role: string
}

@Component({
  selector: 'app-profile-update',
  templateUrl: './profile-update.component.html',
  styleUrls: ['./profile-update.component.scss']
})
export class ProfileUpdateComponent implements OnInit {
  profileForm: FormGroup
  passwordForm: FormGroup
  currentUser: User | null = null
  selectedFile: File | null = null
  previewUrl: SafeUrl | null = null
  isLoading = false
  showPasswordForm = false

  constructor(
    private fb: FormBuilder,
    private http: HttpClient,
    private snackBar: MatSnackBar,
    private sanitizer: DomSanitizer
  ) {
    this.profileForm = this.fb.group({
      username: ['', [Validators.required, Validators.minLength(3), Validators.maxLength(30), Validators.pattern(/^[a-zA-Z0-9_-]+$/)]],
      email: ['', [Validators.required, Validators.email, Validators.maxLength(254)]],
      bio: ['', [Validators.maxLength(500)]]
    })

    this.passwordForm = this.fb.group({
      currentPassword: ['', [Validators.required]],
      newPassword: ['', [Validators.required, Validators.minLength(8), this.passwordStrengthValidator]],
      confirmPassword: ['', [Validators.required]]
    }, { validators: this.passwordMatchValidator })
  }

  ngOnInit(): void {
    this.loadCurrentUser()
  }

  loadCurrentUser(): void {
    this.http.get<User>('/rest/user/profile').subscribe({
      next: (user) => {
        this.currentUser = user
        this.profileForm.patchValue({
          username: user.username,
          email: user.email,
          bio: user.bio || ''
        })
      },
      error: (error) => {
        console.error('Error loading user profile:', error)
        this.showError('Failed to load profile data')
      }
    })
  }

  onFileSelected(event: any): void {
    const file = event.target.files[0]
    if (file) {
      // Validate file type
      const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
      if (!allowedTypes.includes(file.type)) {
        this.showError('Please select a valid image file (JPEG, PNG, GIF, or WebP)')
        return
      }

      // Validate file size (5MB limit)
      if (file.size > 5 * 1024 * 1024) {
        this.showError('File size must be less than 5MB')
        return
      }

      this.selectedFile = file
      
      // Create preview URL
      const reader = new FileReader()
      reader.onload = (e) => {
        this.previewUrl = this.sanitizer.bypassSecurityTrustUrl(e.target?.result as string)
      }
      reader.readAsDataURL(file)
    }
  }

  updateProfile(): void {
    if (this.profileForm.valid) {
      this.isLoading = true
      
      const formData = new FormData()
      formData.append('username', this.profileForm.value.username)
      formData.append('email', this.profileForm.value.email)
      formData.append('bio', this.profileForm.value.bio)
      
      if (this.selectedFile) {
        formData.append('profileImage', this.selectedFile)
      }

      this.http.post('/rest/user/profile', formData).subscribe({
        next: (response: any) => {
          this.isLoading = false
          this.showSuccess('Profile updated successfully!')
          this.currentUser = response.user
          this.selectedFile = null
          this.previewUrl = null
          // Reset file input
          const fileInput = document.getElementById('profileImage') as HTMLInputElement
          if (fileInput) fileInput.value = ''
        },
        error: (error) => {
          this.isLoading = false
          console.error('Profile update error:', error)
          if (error.error && error.error.details) {
            this.showError(error.error.details.join(', '))
          } else {
            this.showError('Failed to update profile. Please try again.')
          }
        }
      })
    } else {
      this.markFormGroupTouched(this.profileForm)
    }
  }

  updatePassword(): void {
    if (this.passwordForm.valid) {
      this.isLoading = true
      
      const passwordData = {
        currentPassword: this.passwordForm.value.currentPassword,
        newPassword: this.passwordForm.value.newPassword
      }

      this.http.post('/rest/user/profile', passwordData).subscribe({
        next: (response: any) => {
          this.isLoading = false
          this.showSuccess('Password updated successfully!')
          this.passwordForm.reset()
          this.showPasswordForm = false
        },
        error: (error) => {
          this.isLoading = false
          console.error('Password update error:', error)
          if (error.error && error.error.details) {
            this.showError(error.error.details.join(', '))
          } else {
            this.showError('Failed to update password. Please check your current password.')
          }
        }
      })
    } else {
      this.markFormGroupTouched(this.passwordForm)
    }
  }

  togglePasswordForm(): void {
    this.showPasswordForm = !this.showPasswordForm
    if (!this.showPasswordForm) {
      this.passwordForm.reset()
    }
  }

  passwordStrengthValidator(control: any) {
    const password = control.value
    if (!password) return null
    
    const hasUpperCase = /[A-Z]/.test(password)
    const hasLowerCase = /[a-z]/.test(password)
    const hasNumbers = /\d/.test(password)
    
    if (!hasUpperCase || !hasLowerCase || !hasNumbers) {
      return { passwordStrength: 'Password must contain at least one uppercase letter, one lowercase letter, and one number' }
    }
    
    return null
  }

  passwordMatchValidator(form: FormGroup) {
    const newPassword = form.get('newPassword')
    const confirmPassword = form.get('confirmPassword')
    
    if (newPassword && confirmPassword && newPassword.value !== confirmPassword.value) {
      confirmPassword.setErrors({ passwordMismatch: true })
      return { passwordMismatch: true }
    }
    
    return null
  }

  markFormGroupTouched(formGroup: FormGroup): void {
    Object.keys(formGroup.controls).forEach(key => {
      const control = formGroup.get(key)
      control?.markAsTouched()
    })
  }

  showSuccess(message: string): void {
    this.snackBar.open(message, 'Close', {
      duration: 3000,
      panelClass: ['success-snackbar']
    })
  }

  showError(message: string): void {
    this.snackBar.open(message, 'Close', {
      duration: 5000,
      panelClass: ['error-snackbar']
    })
  }

  getFieldError(fieldName: string, form: FormGroup): string {
    const field = form.get(fieldName)
    if (field?.errors && field.touched) {
      if (field.errors['required']) return `${fieldName} is required`
      if (field.errors['minlength']) return `${fieldName} must be at least ${field.errors['minlength'].requiredLength} characters`
      if (field.errors['maxlength']) return `${fieldName} must be no more than ${field.errors['maxlength'].requiredLength} characters`
      if (field.errors['email']) return 'Please enter a valid email address'
      if (field.errors['pattern']) return `${fieldName} can only contain letters, numbers, underscores, and hyphens`
      if (field.errors['passwordStrength']) return field.errors['passwordStrength']
      if (field.errors['passwordMismatch']) return 'Passwords do not match'
    }
    return ''
  }
}