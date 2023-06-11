const path = require('path');
const webpack = require('webpack');

module.exports = {
    mode: 'development',
    entry: './App.tsx',
    devtool: 'inline-source-map',
    output: {
        filename: 'main.js',
        path: path.resolve(__dirname, '../public'),
    },
    resolve: {
      extensions: ['.tsx', '.ts', '.js', '.css'],
      fallback: {
            buffer: require.resolve('buffer/')
        },
    },
    plugins: [
        new webpack.ProvidePlugin({
            Buffer: ['buffer', 'Buffer'],
        }),
    ],
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
            },
            {
                test: /\.css$/i,
                use: ["style-loader", "css-loader"],
            }
        ],
    },
}