import os from 'os'
import fs = require('fs')
import challengeUtils = require('../lib/challengeUtils')
import { type NextFunction, type Request, type Response } from 'express'
import path from 'path'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import logEvent from '../lib/loggerElasticsearch' // Importar logEvent para registrar eventos personalizados

const libxml = require('libxmljs')
const vm = require('vm')
const unzipper = require('unzipper')

async function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    await logEvent('file_upload_attempt', {
      fileName: file.originalname,
      status: 'file passed',
      timestamp: new Date()
    })
    next()
  } else {
    await logEvent('file_upload_attempt', {
      status: 'file missing',
      timestamp: new Date()
    })
    res.status(400).send({ error: 'No file was provided' })
  }
}

async function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    await logEvent('zip_file_upload', {
      fileName: file?.originalname,
      size: file?.size,
      timestamp: new Date()
    })

    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const buffer = file.buffer
      const filename = file.originalname.toLowerCase()
      const tempFile = path.join(os.tmpdir(), filename)
      fs.open(tempFile, 'w', function (err, fd) {
        if (err != null) { next(err) }
        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          if (err != null) { next(err) }
          fs.close(fd, function () {
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                const fileName = entry.path
                const absolutePath = path.resolve('uploads/complaints/' + fileName)
                challengeUtils.solveIf(challenges.fileWriteChallenge, () => { return absolutePath === path.resolve('ftp/legal.md') })
                
                // Log individual file entries inside ZIP
                logEvent('zip_file_entry', {
                  parentFileName: file.originalname,
                  extractedFileName: fileName,
                  status: absolutePath.includes(path.resolve('.')) ? 'extracted' : 'skipped',
                  timestamp: new Date()
                })

                if (absolutePath.includes(path.resolve('.'))) {
                  entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName).on('error', function (err) { next(err) }))
                } else {
                  entry.autodrain()
                }
              }).on('error', function (err: unknown) { next(err) })
          })
        })
      })
    }
    res.status(204).end()
  } else {
    next()
  }
}

async function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    await logEvent('file_upload_size_check', {
      fileName: file.originalname,
      size: file.size,
      status: file.size > 100000 ? 'exceeds limit' : 'within limit',
      timestamp: new Date()
    })

    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => { return file.size > 100000 })
  }
  next()
}

async function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname?.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase() || '';
  const allowedTypes = ['pdf', 'xml', 'zip']
  
  await logEvent('file_type_check', {
    fileName: file?.originalname,
    fileType,
    status: allowedTypes.includes(fileType) ? 'allowed' : 'disallowed',
    timestamp: new Date()
  })

  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
    return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip')
  })
  next()
}



async function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    await logEvent('xml_file_upload', {
      fileName: file?.originalname,
      size: file?.size,
      timestamp: new Date()
    })

    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
      const data = file.buffer.toString()
      try {
        const sandbox = { libxml, data }
        vm.createContext(sandbox)
        const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 })
        const xmlString = xmlDoc.toString(false)
        
        // Log detection of potentially dangerous XML content
        await logEvent('xml_file_parsed', {
          fileName: file.originalname,
          containsSensitiveData: utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString),
          timestamp: new Date()
        })

        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => { return (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString)) })
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: any) { // TODO: Remove any
        if (utils.contains(err.message, 'Script execution timed out')) {
          if (challengeUtils.notSolved(challenges.xxeDosChallenge)) {
            challengeUtils.solve(challenges.xxeDosChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + err.message + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  res.status(204).end()
}

module.exports = {
  ensureFileIsPassed,
  handleZipFileUpload,
  checkUploadSize,
  checkFileType,
  handleXmlUpload
}
