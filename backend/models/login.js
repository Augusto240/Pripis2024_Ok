module.exports = (sequelize, DataTypes) => {
    const Login = sequelize.define('Login', {
      idlogin: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
        allowNull: false,
      },
      usuario: {
        type: DataTypes.STRING(150),
        allowNull: false,
      },
      senha: {
        type: DataTypes.STRING(150),
        allowNull: false,
      },

      email: {
        type: Sequelize.STRING,
        allowNull: true, // Permite valores nulos
        unique: true,
    },
    
    });
  
    return Login;
  };
  