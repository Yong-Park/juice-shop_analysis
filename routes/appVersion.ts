import config from 'config'
import { type Request, type Response } from 'express'
import * as utils from '../lib/utils'
import logEvent from '../lib/loggerElasticsearch';

module.exports = function retrieveAppVersion() {
  return async (_req: Request, res: Response) => {
    // Obtener el número de versión solo si está configurado para mostrarse
    const version = config.get('application.showVersionNumber') ? utils.version() : '';
    
    // Log de acceso al endpoint de versión de la aplicación
    await logEvent('app_version_access', {
      status: 'success',
      details: 'Application version accessed',
      version: version || 'hidden' // Registrar si la versión está oculta o se mostró
    });
    
    res.json({ version });
  }
}
