/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')
import logEvent from '../lib/loggerElasticsearch'; // Importa la función de log


const security = require('../lib/insecurity')
const cache = require('../data/datacache')
const challenges = cache.challenges

module.exports = function changePassword () {
  return async ({ query, headers, connection }: Request, res: Response, next: NextFunction) => {
    const currentPassword = query.current
    const newPassword = query.new
    const newPasswordInString = newPassword?.toString()
    const repeatPassword = query.repeat

    // Intento de cambio de contraseña
    await logEvent('password_change_attempt', {
      ip: connection.remoteAddress,
      userAgent: headers['user-agent'],
      status: 'attempt',
      currentPassword: currentPassword,
      newPassword: newPassword,
    });

    if (!newPassword || newPassword === 'undefined') {
      await logEvent('password_change_failed', {
        reason: 'Empty new password',
        ip: connection.remoteAddress,
        userAgent: headers['user-agent'],
        newPassword: newPassword,
      });
      res.status(401).send(res.__('Password cannot be empty.'))
    } else if (newPassword !== repeatPassword) {
      await logEvent('password_change_failed', {
        reason: 'New and repeated password do not match',
        ip: connection.remoteAddress,
        userAgent: headers['user-agent'],
        newPassword: newPassword,
      });
      res.status(401).send(res.__('New and repeated password do not match.'))
    } else {
      const token = headers.authorization ? headers.authorization.substr('Bearer='.length) : null
      const loggedInUser = security.authenticatedUsers.get(token)
      if (loggedInUser) {
        if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password) {
          await logEvent('password_change_failed', {
            reason: 'Incorrect current password',
            userId: loggedInUser.data.id,
            ip: connection.remoteAddress,
            userAgent: headers['user-agent'],
            newPassword: newPassword,
          });
          res.status(401).send(res.__('Current password is not correct.'))
        } else {
          UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => {
            if (user != null) {
              await user.update({ password: newPasswordInString });
              
              // Log del cambio exitoso
              await logEvent('password_change_success', {
                userId: loggedInUser.data.id,
                ip: connection.remoteAddress,
                userAgent: headers['user-agent'],
                newPassword: newPassword,
              });

              user.update({ password: newPasswordInString }).then((user: UserModel) => {
                challengeUtils.solveIf(challenges.changePasswordBenderChallenge, () => { return user.id === 3 && !currentPassword && user.password === security.hash('slurmCl4ssic') })
                res.json({ user })
              }).catch((error: Error) => {
                next(error)
              })
            }
          }).catch((error: Error) => {
            next(error)
          })
        }
      } else {
        // Log de actividad ilegal bloqueada
        await logEvent('illegal_activity', {
          reason: 'Unauthorized access to change password',
          ip: connection.remoteAddress,
          userAgent: headers['user-agent'],
          newPassword: newPassword,
        });
        next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      }
    }
  }
}
