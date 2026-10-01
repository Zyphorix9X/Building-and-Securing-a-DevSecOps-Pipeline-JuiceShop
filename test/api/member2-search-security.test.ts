/*
 * IE3142 Member 2
 * Product Search SQL Injection Regression Tests
 */

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

void describe('Member 2 - Product Search SQL Injection Remediation', () => {
  void it('normal product search still works after remediation', async () => {
    const res = await request(app)
      .get('/rest/products/search?q=o-saft')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(res.body.data.length >= 1)
  })

  void it('SQL injection payload is treated as search data', async () => {
    const res = await request(app)
      .get('/rest/products/search?q=%25%27%20OR%201%3D1%29%29%20--%20')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })
})