import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import healthRouter from './routes/health.js';
import requestsRouter from './routes/requests.js';
import { errorHandler, notFound } from './middleware/error.js';

const app = express();

// Basic security headers
app.use(helmet());

// CORS - allow all origins for now; feature branches should lock this down
app.use(cors());

// Logging
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('dev'));
}

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Routes
app.use('/api/health', healthRouter);
app.use('/api/requests', requestsRouter);

// 404
app.use(notFound);

// Error handler
app.use(errorHandler);

export default app;
