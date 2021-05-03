require("@babel/register")
require("dotenv").config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser')
const passport = require('passport')
const {createProxyMiddleware} = require('http-proxy-middleware');

const {sequelize} = require('./src/models/index')
const pubRoutes = require('./src/routes/public.js')
const apiRoutes = require('./src/routes/api');
const adminRoutes = require('./src/routes/admin');
const oroutes = require('./src/routes/oroutes');
const apiMiddleware = require('./src/middleware/apiAuth').default;
const adminMiddleware = require('./src/middleware/adminAuth').default;

const app = express();

// // proxy middleware options
// const options = {
//     target: 'http://localhost:8080/oauth/google', // target host
//     changeOrigin: true, // needed for virtual hosted sites
//     ws: true, // proxy websockets
//     // pathRewrite: {
//     //     '^http://192.168.8.100:8080/pub/PING': '/pub/PING' , // rewrite path
//     // },
//     router: {
//         // when request.headers.host == 'dev.localhost:3000',
//         // override target 'http://www.example.org' to 'http://localhost:8000'
//         // 'http://192.168.8.100:8080/pub/ABC': 'http://localhost:8080/pub/PING',
//     },
// };
// create the proxy (without context)
// const proxy = createProxyMiddleware(options);

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(passport.initialize());
app.use('/oauth', oroutes)
app.use('/pub', pubRoutes);
app.use('/api', apiMiddleware, apiRoutes);
app.use('/api/admin', apiMiddleware, adminMiddleware, adminRoutes);

app.listen(8080, async () => {
    console.log('app working on 8080')
    await sequelize.sync()
})
