import { Request, Response, NextFunction } from 'express';
import { logger } from '../services/logger.service.js'

export async function log(req: Request, res: Response, next: NextFunction): Promise<void> {
  logger.info('Req was made', req.route.path)
  next()
}

