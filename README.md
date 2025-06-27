# EIP712 Node.js Project

A Node.js application with Express.js framework and ethers.js for Ethereum interactions.

## Features

- Express.js web server
- JSON API endpoints
- Health check endpoint
- Environment variable support
- **Ethers.js integration** for Ethereum blockchain interactions
- EIP-712 typed data signing support

## Getting Started

### Prerequisites

- Node.js (version 14 or higher)
- npm

### Installation

1. Clone the repository or navigate to the project directory
2. Install dependencies:
   ```bash
   npm install
   ```

### Running the Application

Start the development server:
```bash
npm start
```

Or run directly with Node:
```bash
node index.js
```

The application will be available at `http://localhost:3000`

### Available Endpoints

- `GET /` - Welcome message
- `GET /health` - Health check endpoint
- `POST /ethereum/wallet` - Create a new Ethereum wallet
- `POST /ethereum/sign-typed-data` - Sign EIP-712 typed data

## Scripts

- `npm start` - Start the application
- `npm test` - Run tests (to be implemented)
- `npm run dev` - Start in development mode with nodemon

## Environment Variables

- `PORT` - Server port (default: 3000)
- `PRIVATE_KEY` - Ethereum private key for signing (optional)

## Dependencies

- **express** - Web framework
- **ethers** - Ethereum library for interacting with the blockchain

## Project Structure

```
eip712/
├── index.js          # Main application file
├── package.json      # Project configuration
├── README.md         # Project documentation
└── .gitignore        # Git ignore file
```

## Ethereum Features

This project includes ethers.js for:
- Creating and managing Ethereum wallets
- Signing EIP-712 typed data
- Interacting with smart contracts
- Sending transactions
- Reading blockchain data 