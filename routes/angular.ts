import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
import * as utils from '../lib/utils'
import logEvent from '../lib/loggerElasticsearch';

module.exports = function serveAngularClient() {
  return async (req: Request, res: Response, next: NextFunction) => {
    const url = req.originalUrl;
    if (!utils.startsWith(url, '/api') && !utils.startsWith(url, '/rest')) {
      // Log de acceso a la interfaz de usuario
      await logEvent('ui_access', {
        path: url,
        status: 'success',
        details: 'User accessed the Angular frontend'
      });
      res.sendFile(path.resolve('frontend/dist/frontend/index.html'));
    } else {
      // Log de error inesperado de acceso a API o REST desde el frontend
      await logEvent('unexpected_path_access', {
        path: url,
        status: 'error',
        details: 'Unexpected access attempt to API or REST endpoint from frontend'
      });
      next(new Error('Unexpected path: ' + url));
    }
  }
}
