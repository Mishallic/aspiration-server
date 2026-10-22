const express = require('express');
const cors = require('cors');
const passport = require('passport');

const config = require('./config');
const publicRoutes = require('./routes/public');
const apiRoutes = require('./routes/api');
const adminRoutes = require('./routes/admin');
const oauthRoutes = require('./routes/oroutes');
const apiAuth = require('./middleware/apiAuth').default;
const adminAuth = require('./middleware/adminAuth').default;
const { notFound, errorHandler } = require('./middleware/errorHandler');

const app = express();

app.disable('x-powered-by');
app.use(cors({ origin: config.corsOrigin }));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

app.use('/oauth', oauthRoutes);
app.use('/pub', publicRoutes);
app.use('/api/admin', apiAuth, adminAuth, adminRoutes);
app.use('/api', apiAuth, apiRoutes);

app.use(notFound);
app.use(errorHandler);

module.exports = app;
