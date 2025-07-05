const express = require('express');
const { ethers } = require('ethers');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;
require('dotenv').config({ path: '.env.local' });
const forge = require("node-forge");
const {
  initiateSmartContractPlatformClient,
} = require('@circle-fin/smart-contract-platform')
const {
  initiateDeveloperControlledWalletsClient,
} = require('@circle-fin/developer-controlled-wallets')

const circleContractSdk = initiateSmartContractPlatformClient({
  apiKey: process.env.CIRCLE_API_KEY,
  entitySecret: process.env.CIRCLE_ENTITY_SECRET,
})
const client = initiateDeveloperControlledWalletsClient({
  apiKey: process.env.CIRCLE_API_KEY,
  entitySecret: process.env.CIRCLE_ENTITY_SECRET,
})

// Validate Circle environment variables at startup
console.log('🔍 Validating Circle environment variables...');

if (!process.env.CIRCLE_ENTITY_SECRET) {
  throw new Error('CIRCLE_ENTITY_SECRET environment variable is not set');
}
if (!process.env.CIRCLE_PUBLIC_KEY) {
  throw new Error('CIRCLE_PUBLIC_KEY environment variable is not set');
}

console.log(`Entity secret length: ${process.env.CIRCLE_ENTITY_SECRET.length}`);
console.log(`Public key length: ${process.env.CIRCLE_PUBLIC_KEY.length}`);

// Parse public key once for reuse
const circlePublicKey = forge.pki.publicKeyFromPem(process.env.CIRCLE_PUBLIC_KEY);
console.log(`✅ Circle public key parsed successfully`);

// Function to generate fresh entity secret ciphertext (required for each API call)
function generateEntitySecretCiphertext() {
  const entitySecret = forge.util.hexToBytes(process.env.CIRCLE_ENTITY_SECRET);
  const entitySecretCiphertext = circlePublicKey.encrypt(entitySecret, 'RSA-OAEP', { 
    md: forge.md.sha256.create(), 
    mgf1: { md: forge.md.sha256.create() } 
  });
  return forge.util.encode64(entitySecretCiphertext);
}



// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Execute smart contract with EIP-712 signature
app.post('/ethereum/execute-contract', async (req, res) => {
  try {
    const {
      from,
      to,
      signature,
      contractAddress,
      rpcUrl = 'http://localhost:8545'
    } = req.body;

    if (!from || !to || !signature || !contractAddress) {
      return res.status(400).json({ error: 'Missing required parameters: from, to, signature, contractAddress' });
    }

    // Connect to provider and wallet
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    // Use a funded test wallet (Hardhat default account 0)
    const wallet = new ethers.Wallet("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", provider);

    // Contract ABI for the new signature
    const contractABI = [
      "function executeTrade(address from, address to, bytes signature) external"
    ];
    const contract = new ethers.Contract(contractAddress, contractABI, wallet);

    // Call the contract
    let tx;
    try {
      tx = await contract.executeTrade(
        from,
        to,
        signature
      );
    } catch (err) {
      console.error('Execute contract error:', err);
      return res.status(400).json({ error: 'Contract call failed', details: err.message });
    }

    // Wait for transaction to be mined
    let receipt;
    try {
      receipt = await tx.wait();
    } catch (err) {
      return res.status(500).json({ error: 'Transaction failed to be mined', details: err.message });
    }

    res.json({
      success: true,
      transactionHash: tx.hash,
      blockNumber: receipt.blockNumber,
      gasUsed: receipt.gasUsed.toString(),
      message: 'Smart contract executed successfully'
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error during contract execution', message: error.message });
  }
});

// Prepare transaction data for MetaMask execution (backend handles ABI encoding)
app.post('/ethereum/prepare-record-transaction', async (req, res) => {
  try {
    const {
      senderAddress,
      receiverAddress,
      fromAmount,
      fromCurrency,
      toAmount,
      toCurrency,
      signature,
      contractAddress
    } = req.body;

      // Contract ABI for the recordTrade function
    const contractABI = [
      "function recordTrade(address senderAddress, address receiverAddress, uint256 fromAmount, string fromCurrency, uint256 toAmount, string toCurrency, bytes signature) external"
    ];

    // Create contract interface for ABI encoding
    const iface = new ethers.Interface(contractABI);

    // Encode the function call
    const transactionData = iface.encodeFunctionData("recordTrade", [
      senderAddress,
      receiverAddress,
      fromAmount,
      fromCurrency,
      toAmount,
      toCurrency,
      signature
    ]);

    res.json({
      success: true,
      transactionData: transactionData,
      message: 'Transaction Data prepared for MetaMask execution'
    });

  } catch (error) {
    console.error('Prepare Record Trade Transaction error:', error);
    res.status(500).json({ 
      error: 'Failed to prepare transaction data',
      message: error.message 
    });
  }
});

app.post('/circle/prepare-record-transaction', async (req, res) => {
  try {
    const {
      senderAddress,
      receiverAddress,
      fromAmount,
      fromCurrency,
      toAmount,
      toCurrency,
      signature,
      contractAddress
    } = req.body;

    console.log('🚀 Recording trade via Circle Programmable Wallet...');
    console.log('📋 Trade parameters:', {
      senderAddress,
      receiverAddress,
      fromAmount,
      fromCurrency,
      toAmount,
      toCurrency,
      contractAddress,
      signatureLength: signature ? signature.length : 0
    });

    // Generate fresh entity secret ciphertext for this request (required to prevent replay attacks)
    const freshEntitySecretCiphertext = generateEntitySecretCiphertext();

    // Create the transaction using Circle SDK (directly execute, not just prepare)
    // Using recordTradeWithoutSig to bypass signature verification issues with Circle
    const response = await client.createContractExecutionTransaction({
      walletId: process.env.CIRCLE_TREASURY_WALLET_ID,
      contractAddress: contractAddress,
      abiFunctionSignature: 'recordTradeWithoutSig(address,address,uint256,string,uint256,string,bytes)',
      abiParameters: [
        senderAddress,
        receiverAddress,
        fromAmount.toString(),
        fromCurrency,
        toAmount.toString(),
        toCurrency,
        signature
      ],
      fee: {
        type: 'level',
        config: { feeLevel: 'MEDIUM' }
      },
      entitySecretCiphertext: freshEntitySecretCiphertext
    });
    
    const transactionId = response.data.id;
    
    console.log('✅ Circle transaction initiated:', {
      transactionId,
      state: response.data.state
    });

    // Wait for transaction to be mined (poll for completion)
    console.log('⏳ Waiting for transaction to be mined...');
    
    let transaction = null;
    let attempts = 0;
    const maxAttempts = 40; // 4 minutes maximum wait time
    
    while (attempts < maxAttempts) {
      try {
        const txResponse = await client.getTransaction({ id: transactionId });
        transaction = txResponse.data.transaction;
        
        console.log(`⏳ Attempt ${attempts + 1}/${maxAttempts}: Transaction state: ${transaction.state}`);
        console.log(`🔍 Transaction details:`, {
          id: transaction.id,
          state: transaction.state,
          txHash: transaction.txHash || 'Not yet available',
          sourceAddress: transaction.sourceAddress,
          destinationAddress: transaction.destinationAddress,
          transactionType: transaction.transactionType,
          custodyType: transaction.custodyType
        });
        
        if (transaction.state === 'COMPLETE' && transaction.txHash) {
          console.log('✅ Transaction completed successfully!');
          break;
        }
        
        if (transaction.state === 'FAILED') {
          console.log('❌ Transaction failed with details:', transaction);
          throw new Error(`Circle transaction failed immediately: ${transaction.errorReason || transaction.errorCode || 'Unknown error'}. This usually indicates a contract call issue - check function signature, parameters, or contract address.`);
        }
        
        await new Promise(resolve => setTimeout(resolve, 6000)); // Wait 6 seconds
        attempts++;
      } catch (error) {
        console.log(`⚠️  Attempt ${attempts + 1}/${maxAttempts}: Error checking transaction status:`, error.message);
        attempts++;
        await new Promise(resolve => setTimeout(resolve, 6000)); // Wait 6 seconds
      }
    }

    // Handle transaction completion or timeout
    if (!transaction) {
      console.log('⚠️  Transaction polling failed - returning transaction ID for manual tracking');
      return res.json({
        success: true,
        transactionId: transactionId,
        state: 'PENDING',
        message: 'Trade transaction initiated via Circle Programmable Wallet. Transaction is still processing - use the transaction ID to check status manually.',
        note: 'Transaction may still complete. Check Circle dashboard for updates.'
      });
    }

    if (transaction.txHash) {
      const txHash = transaction.txHash;

      console.log('🎉 Trade recorded successfully:', {
        txHash,
        blockHeight: transaction.blockHeight,
        state: transaction.state
      });

      res.json({
        success: true,
        txHash: txHash,
        transactionId: transactionId,
        blockHeight: transaction.blockHeight,
        state: transaction.state,
        message: 'Trade recorded successfully via Circle Programmable Wallet'
      });
    } else {
      console.log('⚠️  Transaction created but hash not available yet - returning transaction ID');
      res.json({
        success: true,
        transactionId: transactionId,
        state: transaction.state,
        message: 'Trade transaction initiated via Circle Programmable Wallet. Transaction is processing - use the transaction ID to check status.',
        note: 'Transaction hash will be available once the transaction is mined on the blockchain.'
      });
    }
    
  } catch (error) {
    console.error('❌ Circle prepare-record-transaction error:', error);
    
    res.status(500).json({ 
      error: error.message,
      details: error.stack,
      troubleshooting: [
        'Check if Circle API keys are properly configured',
        'Verify Circle entity secret and public key',
        'Ensure wallet has sufficient balance for transaction',
        'Check if contract address is valid and deployed',
        'Verify all trade parameters are correct',
        'Check network connectivity to Circle API'
      ]
    });
  }
});


// Deploy smart contract
app.post('/ethereum/deploy-contract', async (req, res) => {
  try {
    const { rpcUrl = 'http://localhost:8545' } = req.body;

    // Create provider and wallet using the first Hardhat account
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    const wallet = new ethers.Wallet("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", provider);

    // Contract ABI and bytecode - we'll need to load this from the compiled artifacts
    const fs = require('fs');
    const path = require('path');
    
    // Read the contract artifact
    const artifactPath = path.join(__dirname, 'artifacts/contracts/TradeContract.sol/TradeContract.json');
    
    if (!fs.existsSync(artifactPath)) {
      return res.status(500).json({ 
        error: 'Contract artifacts not found. Please run "npx hardhat compile" first.' 
      });
    }
    
    const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
    const contractABI = artifact.abi;
    const contractBytecode = artifact.bytecode;

    // Create contract factory
    const contractFactory = new ethers.ContractFactory(contractABI, contractBytecode, wallet);
    
    // Deploy the contract
    const contract = await contractFactory.deploy();
    
    // Wait for deployment to complete
    await contract.waitForDeployment();
    
    // Get the deployed contract address
    const contractAddress = await contract.getAddress();
    
    res.json({
      success: true,
      contractAddress: contractAddress,
      deployer: wallet.address,
      transactionHash: contract.deploymentTransaction().hash,
      message: 'TradeContract deployed successfully'
    });
  } catch (error) {
    console.error('Deploy contract error:', error);
    res.status(500).json({ 
      error: 'Failed to deploy contract',
      message: error.message,
      details: error.stack 
    });
  }
});

// Deploy contract with Circle Programmable Wallet
app.post('/circle/deploy-contract', async (req, res) => {
  try {
    const { networkConfig } = req.body;
    
    // Validate Circle environment variables
    const requiredEnvVars = {
      CIRCLE_API_KEY: process.env.CIRCLE_API_KEY,
      CIRCLE_ENTITY_SECRET: process.env.CIRCLE_ENTITY_SECRET,
      CIRCLE_PUBLIC_KEY: process.env.CIRCLE_PUBLIC_KEY,
      CIRCLE_TREASURY_WALLET_ID: process.env.CIRCLE_TREASURY_WALLET_ID
    };
    
    console.log('🔍 Circle environment variables status:');
    for (const [key, value] of Object.entries(requiredEnvVars)) {
      console.log(`  ${key}: ${value ? '✅ Present' : '❌ Missing'}`);
    }
    
    const missingVars = Object.entries(requiredEnvVars)
      .filter(([key, value]) => !value)
      .map(([key]) => key);
    
    if (missingVars.length > 0) {
      throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
    }
    
    // Use dynamic blockchain from network config, default to Sepolia
    const blockchain = networkConfig?.circleBlockchain || 'ETH-SEPOLIA';
    
    // Load compiled contract
    const artifactPath = path.join(__dirname, 'artifacts/contracts/TradeContract.sol/TradeContract.json');
    const fs = require('fs');
    const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
    const contractABI = artifact.abi;
    const bytecode = artifact.bytecode;

    console.log(`🚀 Deploying contract to ${blockchain} blockchain...`);

    // Generate fresh entity secret ciphertext for this request (required to prevent replay attacks)
    const freshEntitySecretCiphertext = generateEntitySecretCiphertext();
    
    const deploymentParams = {
      name: 'PiFXTradeContract',
      description: 'PiFXTradeContractForTokenSwapsWithEIP712Signatures',
      walletId: process.env.CIRCLE_TREASURY_WALLET_ID,
      blockchain: blockchain, // Use dynamic blockchain
      fee: {
        type: 'level',
        config: {
          feeLevel: 'MEDIUM',
        },
      },
      constructorParameters: [],
      entitySecretCiphertext: freshEntitySecretCiphertext,
      abiJSON: JSON.stringify(contractABI),
      bytecode: bytecode,
    };

    // Debug logging
    console.log('🔍 Circle deployment parameters:', {
      name: deploymentParams.name,
      description: deploymentParams.description,
      walletId: deploymentParams.walletId,
      blockchain: deploymentParams.blockchain,
      fee: deploymentParams.fee,
      constructorParameters: deploymentParams.constructorParameters,
      entitySecretCiphertext: deploymentParams.entitySecretCiphertext ? '✅ Present' : '❌ Missing',
      abiJSON: deploymentParams.abiJSON ? `✅ Present (${deploymentParams.abiJSON.length} chars)` : '❌ Missing',
      bytecode: deploymentParams.bytecode ? `✅ Present (${deploymentParams.bytecode.length} chars)` : '❌ Missing',
    });

    const response = await circleContractSdk.deployContract(deploymentParams)
   
    const contractResponse = response.data;
    const contractId = contractResponse.contractId;
    const transactionId = contractResponse.transactionId;

    console.log('✅ Contract deployment initiated:', {
      contractId,
      transactionId
    });

    // Wait for deployment to complete
    console.log('⏳ Waiting for deployment to complete...');
    
    // Poll for deployment completion
    let deployed = null;
    let attempts = 0;
    const maxAttempts = 30; // 30 attempts = ~5 minutes with 10s intervals
    
    while (attempts < maxAttempts) {
      try {
        deployed = await circleContractSdk.getContract({ id: contractId });
        
        if (deployed.data.contract.contractAddress) {
          console.log('✅ Contract deployed successfully!');
          break;
        }
        
        console.log(`⏳ Attempt ${attempts + 1}/${maxAttempts}: Contract still deploying...`);
        await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds
        attempts++;
      } catch (error) {
        console.log(`⚠️  Attempt ${attempts + 1}/${maxAttempts}: Error checking deployment status:`, error.message);
        attempts++;
        await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds
      }
    }

    if (!deployed || !deployed.data.contract.contractAddress) {
      throw new Error('Contract deployment timeout or failed after maximum attempts');
    }

    const contract = deployed.data.contract;
    const contractAddress = contract.contractAddress; // ✅ Now using the actual deployed address

    console.log('🎉 Contract deployment completed:', {
      contractAddress,
      txHash: contract.txHash,
      deployer: contract.deployerAddress
    });

    // Get transaction details for reference
    const transactionData = await client.getTransaction({
      id: transactionId
    });
    console.log("============> transaction res", transactionData);

    const {id, txHash, deployerWalletID, deploymentTransactionId, deployerAddress} = contract;

    res.json({
      success: true,
      contractAddress: contractAddress,
      deployer: deployerAddress,
      deploymentTransactionId: deploymentTransactionId, 
      transactionHash: txHash,
      contractId: contractId,
      blockchain: blockchain,
      message: `TradeContract deployed successfully via Circle Programmable Wallet on ${blockchain}`
    });

  } catch (err) {
    console.error('❌ Circle deploy-contract error:', err);
    
    // Extract detailed error information
    let errorDetails = {
      message: err.message,
      stack: err.stack,
      status: err.response?.status,
      statusText: err.response?.statusText,
      data: err.response?.data,
      config: err.config ? {
        url: err.config.url,
        method: err.config.method,
        headers: err.config.headers ? Object.keys(err.config.headers) : undefined
      } : undefined
    };
    
    console.error('🔍 Detailed Circle API error:', JSON.stringify(errorDetails, null, 2));
    
    res.status(500).json({ 
      error: err.message,
      details: err.stack,
      circleApiError: err.response?.data || null,
      httpStatus: err.response?.status || null,
      troubleshooting: [
        'Check if Circle API keys are properly configured',
        'Verify Circle entity secret and public key',
        'Ensure wallet has sufficient balance for deployment',
        'Check if contract bytecode is valid',
        'Verify network connectivity to Circle API'
      ]
    });
  }
});

// Execute token swap
app.post('/ethereum/swap-tokens', async (req, res) => {
  try {
    const {
      tradeHash,
      contractAddress,
      rpcUrl = 'http://localhost:8545'
    } = req.body;

    if (!tradeHash || !contractAddress) {
      return res.status(400).json({ 
        error: 'Missing required parameters: tradeHash, contractAddress' 
      });
    }

    // Validate trade hash format
    if (!tradeHash.startsWith('0x') || tradeHash.length !== 66) {
      return res.status(400).json({ 
        error: `Invalid trade hash format: ${tradeHash}. Must be a 32-byte hex string.` 
      });
    }

    // Validate contract address
    if (!ethers.isAddress(contractAddress)) {
      return res.status(400).json({ 
        error: `Invalid contract address format: ${contractAddress}` 
      });
    }

    // Connect to provider and wallet
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    // Use a funded test wallet (Hardhat default account 0)
    const wallet = new ethers.Wallet("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", provider);

    // Contract ABI for the swapTokens function
    const contractABI = [
      "function swapTokens(bytes32 tradeHash) external",
      "function getStoredTrade(bytes32 tradeHash) external view returns (tuple(address from, address to, uint256 fromAmount, string fromCurrency, uint256 toAmount, string toCurrency, uint256 timestamp, bool fromFunded, bool toFunded, bool executed, uint256 fromFundedAmount, uint256 toFundedAmount))",
      "function isTradeReady(bytes32 tradeHash) external view returns (bool)"
    ];
    const contract = new ethers.Contract(contractAddress, contractABI, wallet);

    // Get trade details first to validate
    const trade = await contract.getStoredTrade(tradeHash);
    
    if (trade.from === ethers.ZeroAddress) {
      return res.status(400).json({ 
        error: 'Trade does not exist' 
      });
    }

    if (trade.executed) {
      return res.status(400).json({ 
        error: 'Trade has already been executed' 
      });
    }

    // Check if both parties have provided funds
    if (!trade.fromFunded || !trade.toFunded) {
      return res.status(400).json({ 
        error: 'Both parties must provide funds before executing the swap',
        details: {
          fromFunded: trade.fromFunded,
          toFunded: trade.toFunded
        }
      });
    }

    // Call the swapTokens function
    let tx;
    try {
      tx = await contract.swapTokens(tradeHash);
    } catch (err) {
      console.error('Swap tokens error:', err);
      return res.status(400).json({ 
        error: 'Failed to execute token swap', 
        details: err.message 
      });
    }

    // Wait for transaction to be mined
    let receipt;
    try {
      receipt = await tx.wait();
    } catch (err) {
      return res.status(500).json({ 
        error: 'Transaction failed to be mined', 
        details: err.message 
      });
    }

    res.json({
      success: true,
      transactionHash: tx.hash,
      blockNumber: receipt.blockNumber,
      gasUsed: receipt.gasUsed.toString(),
      tradeHash: tradeHash,
      from: trade.from,
      to: trade.to,
      fromAmount: trade.fromAmount.toString(),
      fromCurrency: trade.fromCurrency,
      toAmount: trade.toAmount.toString(),
      toCurrency: trade.toCurrency,
      executor: wallet.address,
      message: 'Token swap executed successfully'
    });

  } catch (error) {
    console.error('Swap tokens error:', error);
    res.status(500).json({ 
      error: 'Failed to execute token swap',
      message: error.message 
    });
  }
});

// Prepare transaction data for MetaMask execution of swapTokens
app.post('/ethereum/prepare-swap-tokens', async (req, res) => {
  try {
    const {
      tradeHash,
      contractAddress
    } = req.body;

    if (!tradeHash || !contractAddress) {
      return res.status(400).json({ 
        error: 'Missing required parameters: tradeHash, contractAddress' 
      });
    }

    // Validate trade hash format
    if (!tradeHash.startsWith('0x') || tradeHash.length !== 66) {
      return res.status(400).json({ 
        error: `Invalid trade hash format: ${tradeHash}. Must be a 32-byte hex string.` 
      });
    }

    // Validate contract address
    if (!ethers.isAddress(contractAddress)) {
      return res.status(400).json({ 
        error: `Invalid contract address format: ${contractAddress}` 
      });
    }

    // Contract ABI for the swapTokens function
    const contractABI = [
      "function swapTokens(bytes32 tradeHash) external",
      "function getStoredTrade(bytes32 tradeHash) external view returns (tuple(address from, address to, uint256 fromAmount, string fromCurrency, uint256 toAmount, string toCurrency, uint256 timestamp, bool fromFunded, bool toFunded, bool executed, uint256 fromFundedAmount, uint256 toFundedAmount))",
      "function isTradeReady(bytes32 tradeHash) external view returns (bool)"
    ];

    // Create contract interface for ABI encoding
    const iface = new ethers.Interface(contractABI);

    // Encode the function call
    const transactionData = iface.encodeFunctionData("swapTokens", [
      tradeHash
    ]);
    
    res.json({
      success: true,
      transactionData: transactionData,
      message: 'Transaction data prepared for MetaMask execution of swapTokens'
    });

  } catch (error) {
    console.error('Prepare swap tokens error:', error);
    res.status(500).json({ 
      error: 'Failed to prepare transaction data',
      message: error.message 
    });
  }
});

// Prepare transaction data for MetaMask execution of provideFunds
app.post('/ethereum/prepare-provide-funds', async (req, res) => {
  try {
    const {
      tradeHash,
      amount,
      currency,
      contractAddress
    } = req.body;

    if (!tradeHash || !amount || !currency || !contractAddress) {
      return res.status(400).json({ 
        error: 'Missing required parameters: tradeHash, amount, currency, contractAddress' 
      });
    }

    // Validate trade hash format (should be 32 bytes = 66 characters including 0x)
    if (!tradeHash.startsWith('0x') || tradeHash.length !== 66) {
      return res.status(400).json({ 
        error: `Invalid trade hash format: ${tradeHash}. Must be a 32-byte hex string (66 characters including 0x).` 
      });
    }

    // Contract ABI for the provideFunds function
    const contractABI = [
      "function provideFunds(bytes32 tradeHash, uint256 amount) external payable"
    ];

    // Create contract interface for ABI encoding
    const iface = new ethers.Interface(contractABI);

    // Convert ETH amount to wei for both the function parameter and transaction value
    const amountInWei = ethers.parseEther(amount.toString());

    // Encode the function call with amount in wei
    const transactionData = iface.encodeFunctionData("provideFunds", [
      tradeHash,
      amountInWei
    ]);

    // Convert ETH amount to wei for MetaMask display
    const valueInWei = ethers.parseEther(amount.toString());

    res.json({
      success: true,
      transactionData: transactionData,
      value: valueInWei.toString(),
      message: 'Transaction Data prepared for MetaMask execution'
    });

  } catch (error) {
    console.error('Prepare provide funds error:', error);
    res.status(500).json({ 
      error: 'Failed to prepare transaction data',
      message: error.message 
    });
  }
});

// Get all stored trades
app.get('/ethereum/get-trades', async (req, res) => {
  try {
    const { contractAddress } = req.query;

    if (!contractAddress) {
      return res.status(400).json({ 
        error: 'Missing required parameter: contractAddress' 
      });
    }

    // Contract ABI for the getAllStoredTrades function (no pagination)
    const contractABI = [
      "function getAllStoredTrades() external view returns (bytes32[] memory tradeHashesArray, tuple(address senderAddress, address receiverAddress, uint256 fromAmount, string fromCurrency, uint256 toAmount, string toCurrency, uint256 timestamp, bool fromFunded, bool toFunded, bool executed, uint256 fromFundedAmount, uint256 toFundedAmount)[] memory tradesArray)"
    ];

    // Create contract instance
    const provider = new ethers.JsonRpcProvider('http://localhost:8545');
    const contract = new ethers.Contract(contractAddress, contractABI, provider);

    // Call the contract function
    const [tradeHashes, trades] = await contract.getAllStoredTrades();

    // Format the response
    const formattedTrades = trades.map((trade, index) => ({
      tradeHash: tradeHashes[index],
      senderAddress: trade.senderAddress,
      receiverAddress: trade.receiverAddress,
      fromAmount: trade.fromAmount.toString(),
      fromCurrency: trade.fromCurrency,
      toAmount: trade.toAmount.toString(),
      toCurrency: trade.toCurrency,
      timestamp: trade.timestamp.toString(),
      fromFunded: trade.fromFunded,
      toFunded: trade.toFunded,
      executed: trade.executed,
      fromFundedAmount: ethers.formatEther(trade.fromFundedAmount),
      toFundedAmount: ethers.formatEther(trade.toFundedAmount),
      status: trade.executed ? 'executed' : 
              (trade.fromFunded && trade.toFunded) ? 'fully_funded' :
              (trade.fromFunded || trade.toFunded) ? 'partially_funded' : 'pending'
    }));

    res.json({
      success: true,
      trades: formattedTrades,
      message: 'Stored trades retrieved successfully'
    });

  } catch (error) {
    console.error('Get stored trades error:', error);
    res.status(500).json({ 
      error: 'Failed to retrieve stored trades',
      message: error.message 
    });
  }
});

// Get trade count
app.get('/ethereum/trade-count', async (req, res) => {
  try {
    const { contractAddress } = req.query;

    if (!contractAddress) {
      return res.status(400).json({ 
        error: 'Missing required parameter: contractAddress' 
      });
    }

    // Validate contract address
    if (!ethers.isAddress(contractAddress)) {
      return res.status(400).json({ 
        error: `Invalid contract address format: ${contractAddress}` 
      });
    }

    // Contract ABI for the getTradeCount function
    const contractABI = [
      "function getTradeCount() external view returns (uint256)"
    ];

    // Create contract instance
    const provider = new ethers.JsonRpcProvider('http://localhost:8545');
    const contract = new ethers.Contract(contractAddress, contractABI, provider);

    // Call the contract function
    const count = await contract.getTradeCount();

    res.json({
      success: true,
      count: count.toString(),
      message: 'Trade count retrieved successfully'
    });

  } catch (error) {
    console.error('Get trade count error:', error);
    res.status(500).json({ 
      error: 'Failed to retrieve trade count',
      message: error.message 
    });
  }
});

// Get trade by hash
app.get('/ethereum/trades-by-hash', async (req, res) => {
  try {
    const { contractAddress, tradeHash } = req.query;

    if (!contractAddress || !tradeHash) {
      return res.status(400).json({ 
        error: 'Missing required parameters: contractAddress, tradeHash' 
      });
    }

    // Validate contract address
    if (!ethers.isAddress(contractAddress)) {
      return res.status(400).json({ 
        error: `Invalid contract address format: ${contractAddress}` 
      });
    }

    // Validate trade hash format
    if (!tradeHash.startsWith('0x') || tradeHash.length !== 66) {
      return res.status(400).json({ 
        error: `Invalid trade hash format: ${tradeHash}. Must be a 32-byte hex string.` 
      });
    }

    // Contract ABI for the getStoredTrade function
    const contractABI = [
      "function getStoredTrade(bytes32 tradeHash) external view returns (tuple(address senderAddress, address receiverAddress, uint256 fromAmount, string fromCurrency, uint256 toAmount, string toCurrency, uint256 timestamp, bool fromFunded, bool toFunded, bool executed, uint256 fromFundedAmount, uint256 toFundedAmount))"
    ];

    // Create contract instance
    const provider = new ethers.JsonRpcProvider('http://localhost:8545');
    const contract = new ethers.Contract(contractAddress, contractABI, provider);

    // Call the contract function
    const trade = await contract.getStoredTrade(tradeHash);

    // Check if trade exists (senderAddress will be zero address if trade doesn't exist)
    if (trade.senderAddress === ethers.ZeroAddress) {
      return res.status(404).json({ 
        error: 'Trade not found',
        message: `No trade found with hash: ${tradeHash}`
      });
    }

    // Format the response
    const formattedTrade = {
      tradeHash: tradeHash,
      senderAddress: trade.senderAddress,
      receiverAddress: trade.receiverAddress,
      fromAmount: trade.fromAmount.toString(),
      fromCurrency: trade.fromCurrency,
      toAmount: trade.toAmount.toString(),
      toCurrency: trade.toCurrency,
      timestamp: trade.timestamp.toString(),
      fromFunded: trade.fromFunded,
      toFunded: trade.toFunded,
      executed: trade.executed,
      fromFundedAmount: ethers.formatEther(trade.fromFundedAmount),
      toFundedAmount: ethers.formatEther(trade.toFundedAmount),
      status: trade.executed ? 'executed' : 
              (trade.fromFunded && trade.toFunded) ? 'fully_funded' :
              (trade.fromFunded || trade.toFunded) ? 'partially_funded' : 'pending'
    };

    res.json({
      success: true,
      tradeHash: tradeHash,
      trade: formattedTrade,
      pagination: {
        offset: 0,
        limit: 1,
        totalCount: '1',
        hasMore: false
      },
      message: 'Trade found successfully'
    });

  } catch (error) {
    console.error('Get trade by hash error:', error);
    res.status(500).json({ 
      error: 'Failed to retrieve trade by hash',
      message: error.message 
    });
  }
});

app.post('/circle/sign-typed-data', async (req, res) => {
  try {
    const { senderAddress, receiverAddress, fromAmount, fromCurrency, toAmount, toCurrency, contractAddress, networkConfig } = req.body;

    // Use dynamic chain ID from network config, default to Sepolia
    const chainId = networkConfig?.chainId || 11155111;

    const domain = {
      name: 'PiFX',
      version: '1',
      chainId: chainId,
      verifyingContract: contractAddress
    };

    const types = {
      Trade: [
          { name: 'senderAddress', type: 'address' },
          { name: 'receiverAddress', type: 'address' },
          { name: 'fromAmount', type: 'uint256' },
          { name: 'fromCurrency', type: 'string' },
          { name: 'toAmount', type: 'uint256' },
          { name: 'toCurrency', type: 'string' }
      ],
      EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' }
      ]
    };

    const value = {
        senderAddress: senderAddress,
        receiverAddress: receiverAddress,
        fromAmount: fromAmount,
        fromCurrency: fromCurrency,
        toAmount: toAmount,
        toCurrency: toCurrency
    };

    const data = JSON.stringify({
      types: types,
      primaryType: 'Trade',
      domain: domain,
      message: value
    });

    const signatureResult = await client.signTypedData({
      walletId: process.env.CIRCLE_TREASURY_WALLET_ID,
      data,
      memo: "Trade signed with Circle Wallet to confirm trade between Maker and Taker"
    });

    console.log("signatureResult", signatureResult);
    res.json({ signature: signatureResult.data.signature });
  } catch (error) {
    console.error('signTypedData error:', error);
    res.status(500).json({ error: 'Circle signTypedData failed', details: error.message });
  }
});


// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}); 
