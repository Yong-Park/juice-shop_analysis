/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { CardModel } from '../models/card'
import logEvent from '../lib/loggerElasticsearch';


interface displayCard {
  UserId: number
  id: number
  fullName: string
  cardNum: string
  expMonth: number
  expYear: number
}

module.exports.getPaymentMethods = function getPaymentMethods () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const displayableCards: displayCard[] = [];
    const cards = await CardModel.findAll({ where: { UserId: req.body.UserId } });
    
    cards.forEach(card => {
      const displayableCard: displayCard = {
        UserId: card.UserId,
        id: card.id,
        fullName: card.fullName,
        cardNum: '',
        expMonth: card.expMonth,
        expYear: card.expYear
      };
      const cardNumber = String(card.cardNum);
      displayableCard.cardNum = '*'.repeat(12) + cardNumber.substring(cardNumber.length - 4);
      displayableCards.push(displayableCard);
    });

    // Log de consulta de métodos de pago
    await logEvent('get_payment_methods', {
      userId: req.body.UserId,
      cardCount: displayableCards.length,
      timestamp: new Date()
    });

    res.status(200).json({ status: 'success', data: displayableCards });
  };
};


module.exports.getPaymentMethodById = function getPaymentMethodById () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const card = await CardModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } });
    const displayableCard: displayCard = {
      UserId: 0,
      id: 0,
      fullName: '',
      cardNum: '',
      expMonth: 0,
      expYear: 0
    };

    if (card != null) {
      displayableCard.UserId = card.UserId;
      displayableCard.id = card.id;
      displayableCard.fullName = card.fullName;
      displayableCard.expMonth = card.expMonth;
      displayableCard.expYear = card.expYear;

      const cardNumber = String(card.cardNum);
      displayableCard.cardNum = '*'.repeat(12) + cardNumber.substring(cardNumber.length - 4);

      // Log de consulta de un método de pago específico
      await logEvent('get_payment_method_by_id', {
        userId: req.body.UserId,
        cardId: card.id,
        timestamp: new Date()
      });
    }

    if ((card != null) && displayableCard) {
      res.status(200).json({ status: 'success', data: displayableCard });
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected' });
    }
  };
};


module.exports.delPaymentMethodById = function delPaymentMethodById () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const card = await CardModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } });
    
    // Log de eliminación de un método de pago
    await logEvent('delete_payment_method', {
      userId: req.body.UserId,
      cardId: req.params.id,
      status: card ? 'success' : 'failed',
      timestamp: new Date()
    });

    if (card) {
      res.status(200).json({ status: 'success', data: 'Card deleted successfully.' });
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' });
    }
  };
};
