/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Get the currently authenticated user
      const user = security.authenticatedUsers.from(req)

      // Reject request if no authenticated user or basket exists
      if (!user?.data?.id || !user.bid) {
        res.status(401).json({
          error: 'Authentication required'
        })
        return
      }

      // Get requested basket ID
      const id = Number(req.params.id)

      // Validate basket ID and check basket ownership
      if (
        !Number.isSafeInteger(id) ||
        id < 1 ||
        Number(user.bid) !== id
      ) {
        res.status(403).json({
          error: 'Forbidden'
        })
        return
      }

      // Retrieve basket only if it belongs to the authenticated user
      const basket = await BasketModel.findOne({
        where: {
          id,
          UserId: user.data.id
        },
        include: [
          {
            model: ProductModel,
            paranoid: false,
            as: 'Products'
          }
        ]
      })

      // Translate product names
      if (((basket?.Products) != null) && basket.Products.length > 0) {
        for (let i = 0; i < basket.Products.length; i++) {
          basket.Products[i].name = req.__(basket.Products[i].name)
        }
      }

      res.json(utils.queryResultToJson(basket))
    } catch (error) {
      next(error)
    }
  }
}

