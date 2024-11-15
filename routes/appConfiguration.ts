import config from 'config'
import { type Request, type Response } from 'express'
import logEvent from '../lib/loggerElasticsearch';

module.exports = function retrieveAppConfiguration() {
  return async (_req: Request, res: Response) => {
    // Log de acceso al endpoint de configuración
    await logEvent('config_access', {
      status: 'success',
      details: 'Application configuration accessed'
    });
    
    res.json({ config });
  }
}
