// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract TradeContract is EIP712 {
    using ECDSA for bytes32;

    bytes32 public constant TRADE_TYPEHASH = keccak256(
        "Trade(address senderAddress,address receiverAddress,uint256 fromAmount,string fromCurrency,uint256 toAmount,string toCurrency)"
    );

    bytes32 public constant FUNDS_TYPEHASH = keccak256(
        "FundTransfer(bytes32 tradeHash,uint256 amount,string currency)"
    );

    bytes32 public DOMAIN_SEPARATOR;

    struct StoredTrade {
        address senderAddress;
        address receiverAddress;
        uint256 fromAmount;
        string fromCurrency;
        uint256 toAmount;
        string toCurrency;
        uint256 timestamp;
        bool fromFunded;
        bool toFunded;
        bool executed;
        uint256 fromFundedAmount;
        uint256 toFundedAmount;
    }

    mapping(bytes32 => StoredTrade) public storedTrades;
    bytes32[] public tradeHashes;
    
    event TradeRecorded(
        bytes32 indexed tradeHash,
        address indexed senderAddress,
        address indexed receiverAddress,
        uint256 fromAmount,
        string fromCurrency,
        uint256 toAmount,
        string toCurrency,
        uint256 timestamp
    );
    
    event FundsReceived(
        bytes32 indexed tradeHash,
        address indexed funder,
        uint256 amount,
        string currency
    );
    
    event TokensSwapped(
        bytes32 indexed tradeHash,
        address indexed senderAddress,
        address indexed receiverAddress,
        uint256 fromAmount,
        string fromCurrency,
        uint256 toAmount,
        string toCurrency,
        address executor
    );

    constructor() EIP712("PiFX", "1") {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("PiFX")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function hashFXTrade(
        address senderAddress,
        address receiverAddress,
        uint256 fromAmount,
        string calldata fromCurrency,
        uint256 toAmount,
        string calldata toCurrency
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TRADE_TYPEHASH,
                senderAddress,
                receiverAddress,
                fromAmount,
                keccak256(bytes(fromCurrency)),
                toAmount,
                keccak256(bytes(toCurrency))
            )
        );
    }

    /**
     * @dev Record a trade using EIP-712 signature
     * @param senderAddress The address that signed the trade
     * @param receiverAddress The recipient address (should be the contract address)
     * @param fromAmount The amount being traded from
     * @param fromCurrency The currency being traded from
     * @param toAmount The amount being traded to
     * @param toCurrency The currency being traded to
     * @param signature The EIP-712 signature
     */
    function recordTrade(
        address senderAddress,
        address receiverAddress,
        uint256 fromAmount,
        string calldata fromCurrency,
        uint256 toAmount,
        string calldata toCurrency,
        bytes calldata signature
    ) external {
        // Create the digest for EIP-712
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                hashFXTrade(senderAddress, receiverAddress, fromAmount, fromCurrency, toAmount, toCurrency)
            )
        );
        
        // Split the signature into v, r, s
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            // First 32 bytes after offset: r
            r := calldataload(add(signature.offset, 0x00))
            s := calldataload(add(signature.offset, 0x20))
            v := byte(0, calldataload(add(signature.offset, 0x40)))
        }

        // Normalize v if needed (in case it's 0 or 1 instead of 27/28)
        if (v < 27) {
            v += 27;
        }

        address recovered = ecrecover(digest, v, r, s);
        require(recovered == senderAddress, "Trade must be signed by sender");

        // Create a unique trade hash
        bytes32 tradeHash = keccak256(
            abi.encodePacked(
                senderAddress,
                receiverAddress,
                fromAmount,
                fromCurrency,
                toAmount,
                toCurrency,
                block.timestamp
            )
        );

        // Store the trade data
        storedTrades[tradeHash] = StoredTrade({
            senderAddress: senderAddress,
            receiverAddress: receiverAddress,
            fromAmount: fromAmount,
            fromCurrency: fromCurrency,
            toAmount: toAmount,
            toCurrency: toCurrency,
            timestamp: block.timestamp,
            fromFunded: false,
            toFunded: false,
            executed: false,
            fromFundedAmount: 0,
            toFundedAmount: 0
        });

        // Add to trade hashes array
        tradeHashes.push(tradeHash);

        // Emit the trade recorded event
        emit TradeRecorded(tradeHash, senderAddress, receiverAddress, fromAmount, fromCurrency, toAmount, toCurrency, block.timestamp);
    }

    /**
     * @dev Provide funds for a trade (can be called by either party)
     * @param tradeHash The hash of the trade
     * @param amount The amount being provided (in wei, should match msg.value)
     */
    function provideFunds(bytes32 tradeHash, uint256 amount) external payable {
        StoredTrade storage trade = storedTrades[tradeHash];

        bool isSenderParty = (msg.sender == trade.senderAddress);

        if (isSenderParty) {
            // For ETH: verify the correct amount was sent with the transaction
            require(msg.value == amount, "Incorrect ETH amount sent");
            // ETH is already transferred to the contract via msg.value
            
            trade.fromFunded = true;
            trade.fromFundedAmount = amount;
        } else {
            // For ETH: verify the correct amount was sent with the transaction
            require(msg.value == amount, "Incorrect ETH amount sent");
            // ETH is already transferred to the contract via msg.value
            
            trade.toFunded = true;
            trade.toFundedAmount = amount;
        }

        emit FundsReceived(tradeHash, msg.sender, amount, msg.sender == trade.senderAddress ? trade.fromCurrency : trade.toCurrency);

        // Check if both parties have provided funds and automatically execute the swap
        if (trade.fromFunded && trade.toFunded && !trade.executed) {
            _executeSwap(tradeHash, trade);
        }
    }

    /**
     * @dev Internal function to execute the token swap
     * @param tradeHash The hash of the trade
     * @param trade The stored trade data
     */
    function _executeSwap(bytes32 tradeHash, StoredTrade storage trade) internal {
        // Mark trade as executed
        trade.executed = true;

        // Transfer fromFundedAmount from contract to receiverAddress
        (bool success1, ) = payable(trade.receiverAddress).call{value: trade.fromFundedAmount}("");
        require(success1, "ETH transfer to receiver failed");

        // Transfer toFundedAmount from contract to senderAddress
        (bool success2, ) = payable(trade.senderAddress).call{value: trade.toFundedAmount}("");
        require(success2, "ETH transfer to sender failed");
        
        emit TokensSwapped(tradeHash, trade.senderAddress, trade.receiverAddress, trade.fromFundedAmount, trade.fromCurrency, trade.toFundedAmount, trade.toCurrency, msg.sender);
    }

    /**
     * @dev Get a stored trade by hash
     * @param tradeHash The hash of the trade
     * @return The stored trade data
     */
    function getStoredTrade(bytes32 tradeHash) external view returns (StoredTrade memory) {
        return storedTrades[tradeHash];
    }

    /**
     * @dev Get all trade hashes
     * @return Array of all trade hashes
     */
    function getAllTradeHashes() external view returns (bytes32[] memory) {
        return tradeHashes;
    }

    /**
     * @dev Get the total number of stored trades
     * @return The number of stored trades
     */
    function getTradeCount() external view returns (uint256) {
        return tradeHashes.length;
    }

    /**
     * @dev Check if a trade is ready for execution
     * @param tradeHash The hash of the trade
     * @return True if both parties have provided funds
     */
    function isTradeReady(bytes32 tradeHash) external view returns (bool) {
        StoredTrade storage trade = storedTrades[tradeHash];
        return trade.senderAddress != address(0) && trade.fromFunded && trade.toFunded && !trade.executed;
    }

    /**
     * @dev Swap tokens once both parties have provided funds (manual execution)
     * @param tradeHash The hash of the trade to execute
     */
    function swapTokens(bytes32 tradeHash) external {
        StoredTrade storage trade = storedTrades[tradeHash];
        require(trade.senderAddress != address(0), "Trade does not exist");
        require(!trade.executed, "Trade already executed");
        require(trade.fromFunded && trade.toFunded, "Both parties must provide funds first");

        _executeSwap(tradeHash, trade);
    }

    /**
     * @dev Get all stored trades
     * @return tradeHashesArray Array of trade hashes
     * @return tradesArray Array of stored trade data
     */
    function getAllStoredTrades() external view returns (
        bytes32[] memory tradeHashesArray,
        StoredTrade[] memory tradesArray
    ) {
        uint256 totalCount = tradeHashes.length;
        
        tradeHashesArray = new bytes32[](totalCount);
        tradesArray = new StoredTrade[](totalCount);
        
        for (uint256 i = 0; i < totalCount; i++) {
            tradeHashesArray[i] = tradeHashes[i];
            tradesArray[i] = storedTrades[tradeHashes[i]];
        }
    }

    /**
     * @dev Get trade status for a specific trade
     * @param tradeHash The hash of the trade
     * @return 0 = pending, 1 = partially funded, 2 = fully funded, 3 = executed
     */
    function getTradeStatus(bytes32 tradeHash) external view returns (uint8) {
        StoredTrade storage trade = storedTrades[tradeHash];
        require(trade.senderAddress != address(0), "Trade does not exist");
        return _getTradeStatus(trade);
    }

    /**
     * @dev Get the token address for a given currency
     * @param currency The currency symbol
     * @return The token address (address(0) for ETH)
     */
    function _getTokenAddress(string memory currency) internal pure returns (address) {
        // Only ETH is supported, return address(0)
        return address(0);
    }

    /**
     * @dev Internal function to determine trade status
     * @param trade The stored trade
     * @return 0 = pending, 1 = partially funded, 2 = fully funded, 3 = executed
     */
    function _getTradeStatus(StoredTrade storage trade) internal view returns (uint8) {
        if (trade.executed) {
            return 3; // executed
        } else if (trade.fromFunded && trade.toFunded) {
            return 2; // fully funded
        } else if (trade.fromFunded || trade.toFunded) {
            return 1; // partially funded
        } else {
            return 0; // pending
        }
    }

    // Allow the contract to receive ETH
    receive() external payable {}
} 