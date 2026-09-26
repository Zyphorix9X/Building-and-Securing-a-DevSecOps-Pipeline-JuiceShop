import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'

import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('Member 1 - Login security regression test', () => {
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