import app from './server.js';
import { createRequestHandler } from '@vercel/node';

export default createRequestHandler(app);
