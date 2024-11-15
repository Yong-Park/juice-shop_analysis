import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import { decode } from 'jsonwebtoken'
import * as security from '../lib/insecurity'
import logEvent from '../lib/loggerElasticsearch';

async function retrieveUserList(req: Request, res: Response, next: NextFunction) {
  try {
    const users = await UserModel.findAll()

    // Registrar el acceso a la lista de usuarios
    await logEvent('user_list_access', {
      status: 'success',
      action: 'Retrieve user list',
      accessedBy: req.ip, // Opcional: IP de quien hace la solicitud
      userAgent: req.headers['user-agent'] // Opcional: user-agent para identificar el cliente
    });

    res.json({
      status: 'success',
      data: users.map((user) => {
        const userToken = security.authenticatedUsers.tokenOf(user)
        let lastLoginTime: number | null = null
        if (userToken) {
          const parsedToken = decode(userToken, { json: true })
          lastLoginTime = parsedToken ? Math.floor(new Date(parsedToken?.iat ?? 0 * 1000).getTime()) : null
        }

        return {
          ...user.dataValues,
          password: user.password?.replace(/./g, '*'),
          totpSecret: user.totpSecret?.replace(/./g, '*'),
          lastLoginTime
        }
      })
    })
  } catch (error) {
    // Registrar errores en los logs
    await logEvent('user_list_access', {
      status: 'error',
      action: 'Retrieve user list',
      error: error,
      accessedBy: req.ip, // Opcional: IP de quien hace la solicitud
      userAgent: req.headers['user-agent'] // Opcional: user-agent para identificar el cliente
    });
    next(error)
  }
}

export default () => retrieveUserList
