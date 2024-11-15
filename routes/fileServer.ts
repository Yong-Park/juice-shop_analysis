import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'
import { challenges } from '../data/datacache'
import challengeUtils = require('../lib/challengeUtils')
import * as utils from '../lib/utils'
import logEvent from '../lib/loggerElasticsearch' // Importa logEvent para registrar eventos personalizados
const security = require('../lib/insecurity')

module.exports = function servePublicFiles () {
  return async ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      await verify(file, res, next)
    } else {
      // Log de intento de acceso con nombre de archivo no permitido
      await logEvent('file_access_error', {
        file,
        reason: 'File names cannot contain forward slashes',
        timestamp: new Date()
      })
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  async function verify (file: string, res: Response, next: NextFunction) {
    if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
      file = security.cutOffPoisonNullByte(file)

      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })
      verifySuccessfulPoisonNullByteExploit(file)

      // Log de acceso a un archivo permitido
      await logEvent('file_access', {
        file,
        status: 'success',
        timestamp: new Date()
      })

      res.sendFile(path.resolve('ftp/', file))
    } else {
      // Log de intento de acceso con extensión de archivo no permitida
      await logEvent('file_access_error', {
        file,
        reason: 'Only .md and .pdf files are allowed',
        timestamp: new Date()
      })
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
