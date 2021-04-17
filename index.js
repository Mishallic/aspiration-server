require("@babel/register")
require("dotenv").config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser')
const {sequelize} = require('./src/models/index')
const pubRoutes = require('./src/routes/public.js')
const apiRoutes = require('./src/routes/api');
const adminRoutes = require('./src/routes/admin');
const apiMiddleware = require('./src/middleware/apiAuth').default;
const adminMiddleware = require('./src/middleware/adminAuth').default;


const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use('/pub',pubRoutes);
app.use('/api', apiMiddleware, apiRoutes);
app.use('/api/admin', apiMiddleware, adminMiddleware, adminRoutes);


app.listen(8080, async () => {
    console.log('app working on 8080')
    await sequelize.sync()
})