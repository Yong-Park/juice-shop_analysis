/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'
import logEvent from '../lib/loggerElasticsearch'


const security = require('../lib/insecurity')

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    db.reviewsCollection.update(
      { _id: req.body.id },
      { $set: { message: req.body.message } },
      { multi: true }
    ).then(
      async (result: { modified: number, original: Array<{ author: any }> }) => {
        challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 })
        challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 })

        // Registro en Elasticsearch
        await logEvent('update_product_review', {
          userEmail: user?.data?.email || 'unknown',
          reviewId: req.body.id,
          newMessage: req.body.message,
          modificationCount: result.modified,
          isForgedReview: result.original[0]?.author !== user?.data?.email,
          timestamp: new Date()
        })

        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}

// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
