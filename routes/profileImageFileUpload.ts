/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import logger from '../lib/logger'
import logEvent from '../lib/loggerElasticsearch';


import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const fileType = require('file-type')

module.exports = function fileUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const file = req.file;
    const buffer = file?.buffer;
    const uploadedFileType = await fileType.fromBuffer(buffer);

    if (uploadedFileType === undefined) {
      await logEvent('profile_image_upload', {
        status: 'failed',
        reason: 'illegal_file_type',
        userIp: req.socket.remoteAddress,
        timestamp: new Date()
      });

      res.status(500);
      next(new Error('Illegal file type'));
    } else {
      if (uploadedFileType !== null && utils.startsWith(uploadedFileType.mime, 'image')) {
        const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
        
        if (loggedInUser) {
          const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${uploadedFileType.ext}`;
          fs.open(filePath, 'w', function (err, fd) {
            if (err != null) logger.warn('Error opening file: ' + err.message);
            
            // @ts-expect-error FIXME buffer has unexpected type
            fs.write(fd, buffer, 0, buffer.length, null, function (err) {
              if (err != null) logger.warn('Error writing file: ' + err.message);
              fs.close(fd, function () { });
            });
          });

          UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => {
            if (user != null) {
              await user.update({ profileImage: `assets/public/images/uploads/${loggedInUser.data.id}.${uploadedFileType.ext}` });

              // Log de subida de imagen exitosa
              await logEvent('profile_image_upload', {
                userId: loggedInUser.data.id,
                fileType: uploadedFileType.mime,
                filePath,
                status: 'success',
                timestamp: new Date()
              });
            }
          }).catch((error: Error) => {
            next(error);
          });

          res.location(process.env.BASE_PATH + '/profile');
          res.redirect(process.env.BASE_PATH + '/profile');
        } else {
          await logEvent('profile_image_upload', {
            status: 'blocked',
            reason: 'unauthenticated_user',
            userIp: req.socket.remoteAddress,
            timestamp: new Date()
          });

          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
        }
      } else {
        await logEvent('profile_image_upload', {
          status: 'failed',
          reason: 'unsupported_file_type',
          fileType: uploadedFileType?.mime,
          userIp: req.socket.remoteAddress,
          timestamp: new Date()
        });

        res.status(415);
        next(new Error(`Profile image upload does not accept this file type${uploadedFileType ? (': ' + uploadedFileType.mime) : '.'}`));
      }
    }
  };
};
