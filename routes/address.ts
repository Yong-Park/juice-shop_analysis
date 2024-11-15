/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { AddressModel } from '../models/address'
import logEvent from '../lib/loggerElasticsearch';


module.exports.getAddress = function getAddress() {
  return async (req: Request, res: Response) => {
    try {
      const addresses = await AddressModel.findAll({ where: { UserId: req.body.UserId } });
      
      await logEvent('address_retrieval', {
        userId: req.body.UserId,
        status: 'success',
        addresses: addresses,
        details: 'Retrieved user addresses'
      });
      
      res.status(200).json({ status: 'success', data: addresses });
    } catch (error) {
      await logEvent('address_retrieval', {
        userId: req.body.UserId,
        status: 'error',
        error: error
      });
      res.status(500).json({ status: 'error', data: 'An error occurred while retrieving addresses.' });
    }
  };
}


module.exports.getAddressById = function getAddressById() {
  return async (req: Request, res: Response) => {
    try {
      const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } });
      if (address != null) {
        await logEvent('address_retrieval_by_id', {
          userId: req.body.UserId,
          addressId: req.params.id,
          address: address,
          status: 'success',
          details: 'Retrieved address by ID'
        });
        res.status(200).json({ status: 'success', data: address });
      } else {
        await logEvent('address_retrieval_by_id', {
          userId: req.body.UserId,
          addressId: req.params.id,
          address: address,
          status: 'error',
          details: 'Malicious activity detected'
        });
        res.status(400).json({ status: 'error', data: 'Malicious activity detected.' });
      }
    } catch (error) {
      await logEvent('address_retrieval_by_id', {
        userId: req.body.UserId,
        addressId: req.params.id,
        status: 'error',
        error: error
      });
      res.status(500).json({ status: 'error', data: 'An error occurred while retrieving the address.' });
    }
  };
}


module.exports.delAddressById = function delAddressById() {
  return async (req: Request, res: Response) => {
    try {
      const address = await AddressModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } });
      if (address) {
        await logEvent('address_deletion', {
          userId: req.body.UserId,
          addressId: req.params.id,
          address: address,
          status: 'success',
          details: 'Address deleted successfully'
        });
        res.status(200).json({ status: 'success', data: 'Address deleted successfully.' });
      } else {
        await logEvent('address_deletion', {
          userId: req.body.UserId,
          addressId: req.params.id,
          address: address,
          status: 'error',
          details: 'Malicious activity detected'
        });
        res.status(400).json({ status: 'error', data: 'Malicious activity detected.' });
      }
    } catch (error) {
      await logEvent('address_deletion', {
        userId: req.body.UserId,
        addressId: req.params.id,
        status: 'error',
        error: error
      });
      res.status(500).json({ status: 'error', data: 'An error occurred while deleting the address.' });
    }
  };
}

