const mysql = require('mysql2/promise');
const connection = mysql.createPool( {
  host: 'localhost',
  user: 'root',
  database: 'bazma_jwt_auth',
  password: '',
  port: 3306,
  waitForConnections: false,
  connectionLimit: 10,
  queueLimit: 0,
});

module.exports = connection;