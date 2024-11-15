/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response, type NextFunction } from 'express'
import type { Memory as MemoryConfig } from '../lib/config.types'
import { SecurityAnswerModel } from '../models/securityAnswer'
import { UserModel } from '../models/user'
import { challenges } from '../data/datacache'
import logEvent from '../lib/loggerElasticsearch';


import challengeUtils = require('../lib/challengeUtils')
const users = require('../data/datacache').users
const security = require('../lib/insecurity')

module.exports = function resetPassword () {
  return async ({ body, connection }: Request, res: Response, next: NextFunction) => {
    const email = body.email;
    const answer = body.answer;
    const newPassword = body.new;
    const repeatPassword = body.repeat;

    if (!email || !answer) {
      await logEvent('reset_password_attempt', {
        status: 'blocked',
        reason: 'missing_email_or_answer',
        ip: connection.remoteAddress,
        timestamp: new Date()
      });
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress));
    } else if (!newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'));
    } else if (newPassword !== repeatPassword) {
      await logEvent('reset_password_attempt', {
        status: 'failed',
        reason: 'password_mismatch',
        email,
        ip: connection.remoteAddress,
        timestamp: new Date()
      });
      res.status(401).send(res.__('New and repeated password do not match.'));
    } else {
      SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      }).then(async (data: SecurityAnswerModel | null) => {
        if ((data != null) && security.hmac(answer) === data.answer) {
          UserModel.findByPk(data.UserId).then(async (user: UserModel | null) => {
            await user!.update({ password: newPassword });
            verifySecurityAnswerChallenges(user!, answer);
            
            // Log de intento exitoso
            await logEvent('reset_password_attempt', {
              status: 'success',
              email,
              userId: data.UserId,
              timestamp: new Date()
            });

            res.json({ user });
          }).catch((error: unknown) => {
            next(error);
          });
        } else {
          // Log de intento fallido por respuesta de seguridad incorrecta
          await logEvent('reset_password_attempt', {
            status: 'failed',
            reason: 'incorrect_security_answer',
            email,
            ip: connection.remoteAddress,
            timestamp: new Date()
          });
          res.status(401).send(res.__('Wrong answer to security question.'));
        }
      }).catch((error: unknown) => {
        next(error);
      });
    }
  }
}


function verifySecurityAnswerChallenges (user: UserModel, answer: string) {
  challengeUtils.solveIf(challenges.resetPasswordJimChallenge, () => { return user.id === users.jim.id && answer === 'Samuel' })
  challengeUtils.solveIf(challenges.resetPasswordBenderChallenge, () => { return user.id === users.bender.id && answer === 'Stop\'n\'Drop' })
  challengeUtils.solveIf(challenges.resetPasswordBjoernChallenge, () => { return user.id === users.bjoern.id && answer === 'West-2082' })
  challengeUtils.solveIf(challenges.resetPasswordMortyChallenge, () => { return user.id === users.morty.id && answer === '5N0wb41L' })
  challengeUtils.solveIf(challenges.resetPasswordBjoernOwaspChallenge, () => { return user.id === users.bjoernOwasp.id && answer === 'Zaya' })
  challengeUtils.solveIf(challenges.resetPasswordUvoginChallenge, () => { return user.id === users.uvogin.id && answer === 'Silence of the Lambs' })
  challengeUtils.solveIf(challenges.geoStalkingMetaChallenge, () => {
    const securityAnswer = ((() => {
      const memories = config.get<MemoryConfig[]>('memories')
      for (let i = 0; i < memories.length; i++) {
        if (memories[i].geoStalkingMetaSecurityAnswer) {
          return memories[i].geoStalkingMetaSecurityAnswer
        }
      }
    })())
    return user.id === users.john.id && answer === securityAnswer
  })
  challengeUtils.solveIf(challenges.geoStalkingVisualChallenge, () => {
    const securityAnswer = ((() => {
      const memories = config.get<MemoryConfig[]>('memories')
      for (let i = 0; i < memories.length; i++) {
        if (memories[i].geoStalkingVisualSecurityAnswer) {
          return memories[i].geoStalkingVisualSecurityAnswer
        }
      }
    })())
    return user.id === users.emma.id && answer === securityAnswer
  })
}
