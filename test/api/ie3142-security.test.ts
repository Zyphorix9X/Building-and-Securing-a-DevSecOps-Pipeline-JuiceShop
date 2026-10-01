import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'

import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('IE3142 - Member 3 Basket Access Control', () => {
  void it('should reject unauthenticated basket access', async () => {
    const response = await request(app)
      .get('/rest/basket/1')

    assert.equal(response.status, 401)
  })

  void it('should allow an authenticated user to access their own basket', async () => {
    const { token, bid } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })

    assert.ok(token)
    assert.ok(bid)

    const response = await request(app)
      .get(`/rest/basket/${bid}`)
      .set({
        Authorization: `Bearer ${token}`,
        'content-type': 'application/json'
      })

    assert.equal(response.status, 200)
    assert.equal(response.body.data.id, bid)
  })

  void it('should block an authenticated user from accessing another users basket', async () => {
    const { token, bid } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })

    assert.ok(token)
    assert.ok(bid)

    const anotherBasketId = Number(bid) + 1

    const response = await request(app)
      .get(`/rest/basket/${anotherBasketId}`)
      .set({
        Authorization: `Bearer ${token}`,
        'content-type': 'application/json'
      })

    assert.equal(response.status, 403)
  })
})
void describe('IE3142 - Member 2 Search SQL Injection', () => {
  void it('should prevent UNION SQL injection through product search', async () => {
    const maliciousQuery = "' UNION SELECT email, password, 3, 4, 5, 6, 7, 8, 9 FROM Users--"

    const response = await request(app)
      .get('/rest/products/search')
      .query({ q: maliciousQuery })

    assert.equal(response.status, 200)

    const responseText = JSON.stringify(response.body)

    assert.equal(
      responseText.includes('admin@juice-sh.op'),
      false
    )
  })
})
void describe('IE3142 - Member 1 Login SQL Injection', () => {
  void it('should block login SQL injection', async () => {
    const response = await request(app)
      .post('/rest/user/login')
      .send({
        email: "admin@juice-sh.op'-- ",
        password: 'wrong-password-3142'
      })

    assert.equal(response.status, 401)

    assert.equal(
      response.body.authentication?.token,
      undefined
    )
  })
})

void describe('IE3142 - Member 4 Forged Product Review', () => {
  void it('should reject unauthenticated product review creation', async () => {
    const response = await request(app)
      .put('/rest/products/1/reviews')
      .send({
        message: 'IE3142 unauthenticated review test',
        author: 'forged@example.com'
      })

    assert.equal(response.status, 401)
  })

  void it('should prevent an authenticated user from forging the review author', async () => {
    const { token } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })

    assert.ok(token)

    const uniqueMessage = `IE3142 forged review test ${Date.now()}`

    const createResponse = await request(app)
      .put('/rest/products/1/reviews')
      .set({
        Authorization: `Bearer ${token}`,
        'content-type': 'application/json'
      })
      .send({
        message: uniqueMessage,
        author: 'forged@example.com'
      })

    assert.equal(createResponse.status, 201)

    const reviewsResponse = await request(app)
      .get('/rest/products/1/reviews')

    assert.equal(reviewsResponse.status, 200)

    const createdReview = reviewsResponse.body.data.find(
(review: { message: string }) => review.message === uniqueMessage    )

    assert.ok(createdReview)
    assert.equal(createdReview.author, 'jim@juice-sh.op')
    assert.notEqual(createdReview.author, 'forged@example.com')
  })
})
