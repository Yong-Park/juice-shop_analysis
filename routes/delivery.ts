import { type Request, type Response, type NextFunction } from 'express'
import { DeliveryModel } from '../models/delivery'
import logEvent from '../lib/loggerElasticsearch'

const security = require('../lib/insecurity')

module.exports.getDeliveryMethods = function getDeliveryMethods () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const methods = await DeliveryModel.findAll()
    if (methods) {
      const sendMethods = []
      for (const method of methods) {
        sendMethods.push({
          id: method.id,
          name: method.name,
          price: security.isDeluxe(req) ? method.deluxePrice : method.price,
          eta: method.eta,
          icon: method.icon
        })
      }

      // Log de obtención de métodos de entrega
      await logEvent('get_delivery_methods', {
        user: req.user || 'anonymous',
        totalMethods: methods.length,
        deluxeUser: security.isDeluxe(req),
        timestamp: new Date()
      })

      res.status(200).json({ status: 'success', data: sendMethods })
    } else {
      res.status(400).json({ status: 'error' })
    }
  }
}

module.exports.getDeliveryMethod = function getDeliveryMethod () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const method = await DeliveryModel.findOne({ where: { id: req.params.id } })
    if (method != null) {
      const sendMethod = {
        id: method.id,
        name: method.name,
        price: security.isDeluxe(req) ? method.deluxePrice : method.price,
        eta: method.eta,
        icon: method.icon
      }

      // Log de obtención de un método de entrega específico
      await logEvent('get_delivery_method', {
        user: req.user || 'anonymous',
        methodId: method.id,
        methodName: method.name,
        deluxeUser: security.isDeluxe(req),
        timestamp: new Date()
      })

      res.status(200).json({ status: 'success', data: sendMethod })
    } else {
      res.status(400).json({ status: 'error' })
    }
  }
}
