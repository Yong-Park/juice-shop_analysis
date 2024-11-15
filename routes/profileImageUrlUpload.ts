/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import logger from '../lib/logger'
import logEvent from '../lib/loggerElasticsearch';


import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const request = require('request')

module.exports = function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl;
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token);

      // Detecta posible ataque SSRF
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) {
        req.app.locals.abused_ssrf_bug = true;
        
        await logEvent('profile_image_url_upload', {
          status: 'failed',
          reason: 'ssrf_attempt_detected',
          userIp: req.socket.remoteAddress,
          timestamp: new Date(),
          url
        });
      }

      if (loggedInUser) {
        const imageRequest = request
          .get(url)
          .on('error', async function (err: unknown) {
            await UserModel.findByPk(loggedInUser.data.id)
              .then(async (user: UserModel | null) => await user?.update({ profileImage: url }))
              .catch((error: Error) => { next(error) });

            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`);

            // Log de error al obtener la imagen
            await logEvent('profile_image_url_upload', {
              userId: loggedInUser.data.id,
              status: 'failed',
              reason: 'error_retrieving_image',
              userIp: req.socket.remoteAddress,
              url,
              timestamp: new Date(),
              error: utils.getErrorMessage(err)
            });
          })
          .on('response', async function (res: Response) {
            const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg';
            const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`;

            if (res.statusCode === 200) {
              imageRequest.pipe(fs.createWriteStream(filePath));

              await UserModel.findByPk(loggedInUser.data.id)
                .then(async (user: UserModel | null) => await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }))
                .catch((error: Error) => { next(error) });

              // Log de carga exitosa
              await logEvent('profile_image_url_upload', {
                userId: loggedInUser.data.id,
                status: 'success',
                url,
                filePath,
                timestamp: new Date()
              });
            } else {
              await UserModel.findByPk(loggedInUser.data.id)
                .then(async (user: UserModel | null) => await user?.update({ profileImage: url }))
                .catch((error: Error) => { next(error) });
            }
          });
      } else {
        // Log de actividad ilegal bloqueada
        await logEvent('profile_image_url_upload', {
          status: 'blocked',
          reason: 'unauthenticated_user',
          userIp: req.socket.remoteAddress,
          timestamp: new Date(),
          url
        });

        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
      }
    }
    res.location(process.env.BASE_PATH + '/profile');
    res.redirect(process.env.BASE_PATH + '/profile');
  };
};
