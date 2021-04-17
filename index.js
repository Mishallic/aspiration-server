require("@babel/register")
require("dotenv").config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser')
const app = express();
const pubRoutes = require('./src/routes/public.js')
const {sequelize} = require('./src/models/index')

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}))

app.use(pubRoutes);
app.use('/api', apiMiddleware, apiRoutes);
app.use('/api/admin', apiMiddleware, adminMiddleware, adminRoutes);


app.listen(8080, async () => {
    console.log('app working on 8080')
    await sequelize.sync()
})