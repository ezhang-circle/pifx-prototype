#!/bin/bash

echo "🔨 Compiling smart contracts..."
npx hardhat compile

if [ $? -eq 0 ]; then
    echo "✅ Compilation successful!"
    echo "🚀 Starting server..."
    node index.js
else
    echo "❌ Compilation failed!"
    exit 1
fi 