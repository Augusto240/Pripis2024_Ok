var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var cors = require('cors');
var bodyParser = require('body-parser');
var Sequelize = require('sequelize');
var dbConfig = require('./config/dbentrada');
var swaggerJSDoc = require('swagger-jsdoc');
var swaggerUi = require('swagger-ui-express');

var indexRouter = require('./routes/index');
var alunocarroRouter = require('./routes/alunocarro');
var loginRouter = require('./routes/login');
var placaRouter = require('./routes/placa');
var entradaRouter = require('./routes/entrada');
var mqttRouter = require('./routes/mqtt');
require('dotenv').config();

var app = express();

app.use(cors({
    origin: "*",
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE'
  }));
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
const opcoes = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Controle de entrada de veículos',
      version: '1.0.0',
      description: 'API que insere, deleta, edita e consulta dados de condutores e seus veículos autorizados a entrar no IFRN - Campus Parnamirim',
    },
  },
  apis: ['./routes/*.js'],
};

const swaggerSpec = swaggerJSDoc(opcoes);

app.use('/', indexRouter);
app.use('/alunocarro', alunocarroRouter);
app.use('/login', loginRouter);
app.use('/placa', placaRouter);
app.use('/entrada', entradaRouter);
app.use('/mqtt', mqttRouter);
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
const sequelize = new Sequelize(dbConfig);

//aqui eu fiz uma alteração pra exportar o app e o sequelize
//aqui está a forma como era antes

//module.exports = app, sequelize;

//aqui está a forma como eu fiz agora pra ver se resolve um erro que estava dando
module.exports = { app, sequelize };

//teste de rota simples pra ver se ta tudo ok
app.get('/api', (req, res) => {
  res.send('API está funcionando!');
});
