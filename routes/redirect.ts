/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import utils = require('../lib/utils')
import challengeUtils = require('../lib/challengeUtils')
import { type Request, type Response, type NextFunction } from 'express'
import { challenges } from '../data/datacache'
import logEvent from '../lib/loggerElasticsearch';

const security = require('../lib/insecurity')

module.exports = function performRedirect () {
  return async ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string;

    if (security.isRedirectAllowed(toUrl)) {
      // Log de redirección permitida
      await logEvent('redirect', {
        status: 'success',
        url: toUrl,
        timestamp: new Date()
      });

      challengeUtils.solveIf(
        challenges.redirectCryptoCurrencyChallenge, 
        () => toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' || 
              toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' || 
              toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
      );

      challengeUtils.solveIf(
        challenges.redirectChallenge, 
        () => isUnintendedRedirect(toUrl)
      );

      res.redirect(toUrl);
    } else {
      // Log de redirección no reconocida o sospechosa
      await logEvent('redirect', {
        status: 'blocked',
        reason: 'unrecognized_url',
        url: toUrl,
        timestamp: new Date()
      });

      res.status(406);
      next(new Error('Unrecognized target URL for redirect: ' + toUrl));
    }
  };
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true;
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl);
  }
  return unintended;
}
