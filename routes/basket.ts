import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'
import challengeUtils = require('../lib/challengeUtils')
import logEvent from '../lib/loggerElasticsearch'; // Importa la función de log personalizada

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
const security = require('../lib/insecurity')

module.exports = function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.params.id;
    try {
      const basket = await BasketModel.findOne({ 
        where: { id }, 
        include: [{ model: ProductModel, paranoid: false, as: 'Products' }] 
      });

      // Detecta y resuelve el desafío si el usuario accede a una canasta no autorizada
      challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
        const user = security.authenticatedUsers.from(req);
        return user && id && id !== 'undefined' && id !== 'null' && id !== 'NaN' && user.bid && user.bid != id; // eslint-disable-line eqeqeq
      });

      if (basket) {
        // Registra el evento de acceso a la canasta
        const user = security.authenticatedUsers.from(req);
        await logEvent('basket_access', {
          basketId: id,
          userId: user?.data.id || 'anonymous',
          products: basket.Products?.map(product => ({
            productId: product.id,
            productName: req.__(product.name),
            price: product.price,
            description: product.description
          })) || [], // Manejo en caso de que Products sea undefined
          message: 'Basket accessed successfully',
          status: 'success'
        });

        // Traduce los nombres de los productos si hay productos en la canasta
        if (basket.Products && basket.Products.length > 0) {
          for (let i = 0; i < basket.Products.length; i++) {
            basket.Products[i].name = req.__(basket.Products[i].name);
          }
        }

        res.json(utils.queryResultToJson(basket));
      } else {
        await logEvent('basket_access', {
          basketId: id,
          userId: 'unknown',
          message: 'Attempt to access non-existent basket',
          status: 'failure'
        });
        res.status(404).json({ error: 'Basket not found' });
      }
    } catch (error) {
      await logEvent('basket_access_error', {
        basketId: id,
        error: error,
        status: 'error',
        message: 'Error retrieving basket'
      });
      next(error);
    }
  };
};
