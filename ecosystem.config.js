module.exports = {
  apps : [{
    name: 'ChatApp',
    script: './Server.js',
    interpreter: 'node',
    env: {
      NODE_ENV: 'production'
    }
  }]
};
