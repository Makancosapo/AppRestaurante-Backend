const sql = require('mssql');

const configuration = {
  user: 'sa',
  password: 'MegamanX61988',
  server: 'localhost\\SQLEXPRESS',
  database:'Restaurante',
  options: {
    encrypt: false,
    trustServerCertificate: true
  },

};

const poolConnection = new sql.ConnectionPool(configuration)
    .connect()
    .then((pool) => {
        console.log('Yujuuu estas conectado!');
        return pool;
    })
    .catch((error)=> {
        console.error('No, no nos hemos conectado :C.',error); 
        throw error;
    })

module.exports = {
    sql,
    poolConnection,

}

