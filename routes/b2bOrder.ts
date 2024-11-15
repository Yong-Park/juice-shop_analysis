import vm = require('vm')
import { type Request, type Response, type NextFunction } from 'express'
import challengeUtils = require('../lib/challengeUtils')
import logEvent from '../lib/loggerElasticsearch'; // Importar el log personalizado

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
const security = require('../lib/insecurity')
const safeEval = require('notevil')

module.exports = function b2bOrder () {
  return async ({ body }: Request, res: Response, next: NextFunction) => {
    const orderLinesData = body.orderLinesData || ''
    const cid = body.cid;
    const orderNo = uniqueOrderNumber();
    const paymentDue = dateTwoWeeksFromNow();

    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      try {
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })

        // Log exitoso si el pedido fue procesado sin errores
        await logEvent('b2b_order_processed', {
          cid,
          orderNo,
          paymentDue,
          orderLinesData,
          status: 'success',
          message: 'B2B order processed successfully'
        });

        res.json({ cid, orderNo, paymentDue })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })

          // Log cuando hay un error de timeout
          await logEvent('b2b_order_error', {
            cid,
            orderLinesData,
            error: 'Script execution timed out',
            status: 'error',
            message: 'Order processing timed out, likely due to an infinite loop'
          });

          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })

          // Log en caso de otros errores
          await logEvent('b2b_order_error', {
            cid,
            orderLinesData,
            error: utils.getErrorMessage(err),
            status: 'error',
            message: 'An error occurred during order processing'
          });

          next(err)
        }
      }
    } else {
      // Log si el pedido fue procesado sin el desafío RCE habilitado
      await logEvent('b2b_order_processed', {
        cid,
        orderNo,
        paymentDue,
        orderLinesData,
        status: 'success',
        message: 'B2B order processed without RCE challenge'
      });

      res.json({ cid, orderNo, paymentDue })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
