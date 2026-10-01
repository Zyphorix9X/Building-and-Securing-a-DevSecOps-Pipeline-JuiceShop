/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { reviewsCollection } from '../data/mongodb'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function createProductReviews () {
  return async (req: Request, res: Response) => {

    const user = security.authenticatedUsers.from(req)

    if (!user?.data?.email) {
      res.status(401).json({
        error: 'Authentication required'
      })
      return
    }

    const productId = Number(req.params.id)
    const message = req.body.message

    if (
      !Number.isSafeInteger(productId) ||
      productId < 1 ||
      typeof message !== 'string' ||
      message.trim().length === 0 ||
      message.length > 1000
    ) {
      res.status(400).json({
        error: 'Invalid review data'
      })
      return
    }

    try {
      await reviewsCollection.insert({
        product: productId,
        message,
        author: user.data.email,
        likesCount: 0,
        likedBy: []
      })

      res.status(201).json({
        status: 'success'
      })
      
    } catch {
      res.status(500).json({
        error: 'Unable to create review'
      })
    }
  }
}
