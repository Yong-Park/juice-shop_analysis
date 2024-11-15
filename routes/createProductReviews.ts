import { type Request, type Response } from 'express'
import challengeUtils = require('../lib/challengeUtils')
import { reviewsCollection } from '../data/mongodb'
import logEvent from '../lib/loggerElasticsearch'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

const security = require('../lib/insecurity')

module.exports = function productReviews () {
  return async (req: Request, res: Response) => {
    const user = security.authenticatedUsers.from(req)
    
    // Verificar si el comentario está siendo falsificado y resolver el desafío si es el caso
    const isForgedReview = user && user.data.email !== req.body.author
    challengeUtils.solveIf(challenges.forgedReviewChallenge, () => isForgedReview)

    try {
      await reviewsCollection.insert({
        product: req.params.id,
        message: req.body.message,
        author: req.body.author,
        likesCount: 0,
        likedBy: []
      })

      // Log para la creación de una reseña de producto
      await logEvent('product_review_creation', {
        productId: req.params.id,
        author: req.body.author,
        message: req.body.message,
        isForgedReview,
        timestamp: new Date()
      })

      res.status(201).json({ status: 'success' })
    } catch (err) {
      res.status(500).json(utils.getErrorMessage(err))
    }
  }
}
