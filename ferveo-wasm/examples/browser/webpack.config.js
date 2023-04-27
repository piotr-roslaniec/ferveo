// Generated using webpack-cli https://github.com/webpack/webpack-cli

const CopyWebpackPlugin = require("copy-webpack-plugin");

const path = require("path");
const isProduction = process.env.NODE_ENV == "production";

const config = {
  entry: "./bootstrap.js",
  output: {
    path: path.resolve(__dirname, "dist"),
  },
  devServer: {
    open: true,
    host: "localhost",
  },
  plugins: [new CopyWebpackPlugin({ patterns: ["index.html"]})],
  module: {
    rules: [
      {
        test: /\.(eot|svg|ttf|woff|woff2|png|jpg|gif)$/i,
        type: "asset",
      },

      // Add your rules for custom modules here
      // Learn more about loaders from https://webpack.js.org/loaders/
    ],
  },
  experiments: {
    asyncWebAssembly: true,
  }
};

module.exports = () => {
  if (isProduction) {
    config.mode = "production";
  } else {
    config.mode = "development";
  }
  return config;
};
