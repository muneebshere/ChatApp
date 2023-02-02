const path = require('path');

module.exports = {
    mode: 'development',
    entry: './App.tsx',
    devtool: 'inline-source-map',
    output: {
        filename: 'main.js',
        path: path.resolve(__dirname, '../public'),
    },
    resolve: {
      extensions: ['.tsx', '.ts', '.js']
    },
    module: {
        rules: [
            {
                test: /\.[j|t]s[x]?$/,
                exclude: /node_modules/,
                use: {
                    loader: 'babel-loader',
                    options: {
                        presets: ['@babel/preset-react', '@babel/preset-typescript']
                    }
                }
            }
        ],
    },
}