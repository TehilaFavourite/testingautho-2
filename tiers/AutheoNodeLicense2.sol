// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import "../AutheoCentralStore.sol";

/**
 * @title AutheoNodeLicense1
 * @dev ERC721 contract for issuing Delegate Node Licenses. Supports payments in ETH, USDT and USDC.
 * @author Shiv Sharma - Zeeve
 */
contract AutheoNodeLicense2 is ERC721, ReentrancyGuard {
    using Strings for uint256;

    // Reference to the AutheoCentralStore contract for price feeds, referrals and token checks
    AutheoCentralStore public immutable autheoCentralStore;

    // Admin address with special privileges
    address public admin;

    // Address for receiving payments (funds) of the smart contract
    address public paymentReceiver;

    // Total supply of node licenses
    uint256 public immutable totalNodes;

    // Tracks the next available token ID
    uint256 public _nextTokenId;

    // Base URI for token metadata
    string private _baseTokenURI;

    // Price per node in USD (fixed rate)
    uint256 public immutable nodePriceInUSD;

    // Current tier info
    string public tier;

    // Mapping to track mint timestamps for token locking mechanism
    mapping(uint256 => uint256) public tokenMintTimestamp;

    // Time period for which NFTs remain locked (1 year)
    uint256 public constant LOCK_PERIOD = 365 days;

    /**
     * @dev Events to notify about contract updates.
     */
    event AdminUpdated(address indexed newAdmin, address indexed oldAdmin);

    event PaymentReceiverUpdated(
        address indexed newPaymentReceiver,
        address indexed oldPaymentReceiver
    );

    event TradeOrder(
        address indexed sender,
        uint256 quantity,
        string paymentMethod,
        string referralCode,
        uint256 referredCommission,
        uint256 referrerCommission,
        uint256 contractAmount
    );

    event ETHWithdrawn(address indexed paymentReceiver, uint256 amount);

    event TokensWithdrawn(
        address indexed paymentReceiver,
        address token,
        uint256 amount
    );

    /**
     * @dev Constructor to initialize the contract with necessary parameters.
     * @param _totalNodes Total number of node licenses available
     * @param baseTokenURI Base URI for metadata of NFTs
     * @param _tier Current tier info
     * @param _paymentReceiver Address of the payment receiver
     * @param _autheoCentralStore Address of the Autheo Central Store contract
     * @param _nodePriceInUSD Price of each node in USD
     */
    constructor(
        uint256 _totalNodes,
        string memory baseTokenURI,
        string memory _tier,
        address _paymentReceiver,
        address _autheoCentralStore,
        uint256 _nodePriceInUSD
    ) ERC721("Autheo Node License", "ANL") {
        require(_paymentReceiver != address(0), "Not a valid address");
        require(_autheoCentralStore != address(0), "Not a valid address");

        admin = msg.sender;
        totalNodes = _totalNodes;
        _baseTokenURI = baseTokenURI;
        tier = _tier;
        paymentReceiver = _paymentReceiver;
        autheoCentralStore = AutheoCentralStore(_autheoCentralStore);
        nodePriceInUSD = _nodePriceInUSD;
    }

    /**
     * @dev Transfers admin role to a new address.
     * @param newAdmin Address of the new admin
     */
    function transferAdminRole(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Not a valid address");
        admin = newAdmin;

        emit AdminUpdated(newAdmin, msg.sender);
    }

    /**
     * @dev Updates the payment receiver address.
     * @param _paymentReceiver New address for payment receiver
     */
    function updatePaymentReceiver(
        address _paymentReceiver
    ) external onlyAdmin {
        require(_paymentReceiver != address(0), "Not a valid address");

        emit PaymentReceiverUpdated(_paymentReceiver, paymentReceiver);

        paymentReceiver = _paymentReceiver;
    }

    /**
     * @dev Mints node licenses using ETH.
     * @param _quantity Number of node licenses to mint
     */
    function mint(
        uint256 _quantity,
        string memory referralCode
    ) public payable nonReentrant {
        require(_quantity != 0, "Quantity is 0");
        if (autheoCentralStore.internalAccounts(msg.sender)) {
            require(
                autheoCentralStore.userHoldings(msg.sender) + _quantity <=
                    autheoCentralStore.internalWalletMaxHoldings(),
                "Limit exceeded"
            );
        } else {
            require(
                autheoCentralStore.userHoldings(msg.sender) + _quantity <=
                    autheoCentralStore.perUserCap(),
                "Limit exceeded"
            );
        }

        require(_nextTokenId + _quantity <= totalNodes, "Limit exhausted");

        require(
            autheoCentralStore.isBlackListed(msg.sender) == false,
            "Blacklisted User"
        );

        require(autheoCentralStore.isKYC(msg.sender), "User kyc is not valid");

        uint256 totalCost = _quantity *
            (nodePriceInUSD * autheoCentralStore.getUsdPriceInEth());

        uint256 referredCommission = 0;

        if (bytes(referralCode).length != 0) {
            require(
                autheoCentralStore.isActiveReferral(referralCode) == true,
                "Referral Code is not active"
            );

            referredCommission =
                (totalCost *
                    autheoCentralStore.referredCommissionPercentage()) /
                100;
            totalCost -= referredCommission;
        }

        require(msg.value >= totalCost, "Insufficient ETH");

        (bool success, ) = msg.sender.call{value: msg.value - totalCost}("");

        require(success, "ETH transfer failed");

        uint256 referrerCommission = 0;

        // referral check
        if (bytes(referralCode).length != 0) {
            address referree = autheoCentralStore.referralCodeToAddress(
                referralCode
            );

            uint256 referrerCommissionPercentage = autheoCentralStore
                .referrerCommissionPercentage();

            referrerCommission =
                (totalCost * referrerCommissionPercentage) /
                100;

            payable(referree).transfer(referrerCommission);
        }

        autheoCentralStore.updateHoldings(msg.sender, _quantity);

        for (uint256 i = 0; i < _quantity; ++i) {
            uint256 tokenId = ++_nextTokenId;
            _safeMint(msg.sender, tokenId);
            tokenMintTimestamp[tokenId] = block.timestamp; // Store mint timestamp
        }

        emit TradeOrder(
            msg.sender,
            _quantity,
            "ETH",
            referralCode,
            referredCommission,
            referrerCommission,
            totalCost - referrerCommission
        );
    }

    /**
     * @dev Mints node licenses using USDC or USDT.
     * @param _token Address of the stablecoin (USDC or USDT)
     * @param _quantity Number of node licenses to mint
     */
    function mintWithUSDCOrUSDT(
        address _token,
        uint256 _quantity,
        string memory referralCode
    ) external nonReentrant {
        require(
            autheoCentralStore.supportedTokens(_token) == true,
            "Unsupported token"
        );
        require(_quantity != 0, "Quantity is 0");

        if (autheoCentralStore.internalAccounts(msg.sender)) {
            require(
                autheoCentralStore.userHoldings(msg.sender) + _quantity <=
                    autheoCentralStore.internalWalletMaxHoldings(),
                "Limit exceeded"
            );
        } else {
            require(
                autheoCentralStore.userHoldings(msg.sender) + _quantity <=
                    autheoCentralStore.perUserCap(),
                "Limit exceeded"
            );
        }

        require(_nextTokenId + _quantity <= totalNodes, "Limit exhausted");

        require(
            autheoCentralStore.isBlackListed(msg.sender) == false,
            "Blacklisted User"
        );

        require(autheoCentralStore.isKYC(msg.sender), "User kyc is not valid");

        uint256 totalCost = _quantity * nodePriceInUSD * 10 ** 6;

        IERC20 paymentToken = IERC20(_token);

        uint256 referredCommission = 0;

        if (bytes(referralCode).length != 0) {
            require(
                autheoCentralStore.isActiveReferral(referralCode) == true,
                "Referral Code is not active"
            );

            referredCommission =
                (totalCost *
                    autheoCentralStore.referredCommissionPercentage()) /
                100;

            totalCost -= referredCommission;
        }
        require(
            paymentToken.allowance(msg.sender, address(this)) >= totalCost,
            "Insufficient token allowance"
        );

        bool success = paymentToken.transferFrom(
            msg.sender,
            address(this),
            totalCost
        );
        require(success, "Token transfer failed");

        uint256 referrerCommission = 0;

        // referral check
        if (bytes(referralCode).length != 0) {
            address referree = autheoCentralStore.referralCodeToAddress(
                referralCode
            );

            uint256 referrerCommissionPercentage = autheoCentralStore
                .referrerCommissionPercentage();

            referrerCommission =
                (totalCost * referrerCommissionPercentage) /
                100;

            paymentToken.transfer(referree, referrerCommission);
        }

        autheoCentralStore.updateHoldings(msg.sender, _quantity);

        for (uint256 i = 0; i < _quantity; ++i) {
            uint256 tokenId = ++_nextTokenId;
            _safeMint(msg.sender, tokenId);
            tokenMintTimestamp[tokenId] = block.timestamp; // Store mint timestamp
        }

        emit TradeOrder(
            msg.sender,
            _quantity,
            "USDC/USDT",
            referralCode,
            referredCommission,
            referrerCommission,
            totalCost - referrerCommission
        );
    }

    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        require(
            block.timestamp >= tokenMintTimestamp[tokenId] + LOCK_PERIOD,
            "NFT locked for 12 months"
        );
        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory data
    ) public virtual override {
        require(
            block.timestamp >= tokenMintTimestamp[tokenId] + LOCK_PERIOD,
            "NFT locked for 12 months"
        );
        super.safeTransferFrom(from, to, tokenId, data);
    }

    /**
     * @dev Withdraws ETH from the contract to the payment receivers.
     */
    function withdraw() public onlyAdmin nonReentrant {
        uint256 totalETHBalance = address(this).balance;

        require(totalETHBalance > 0, "No ETH to withdraw");

        // Emit event
        emit ETHWithdrawn(paymentReceiver, totalETHBalance);
        (bool success1, ) = paymentReceiver.call{value: totalETHBalance}("");
        require(success1, "ETH transfer to paymentReceiver failed");
    }

    /**
     * @dev Withdraws ERC20 tokens from the contract to the payment receivers.
     * @param _token Address of the ERC20 token to withdraw (USDC or USDT)
     */
    function withdrawTokens(address _token) external onlyAdmin nonReentrant {
        require(
            autheoCentralStore.supportedTokens(_token) == true,
            "Unsupported token"
        );
        IERC20 token = IERC20(_token);

        uint256 tokenBalance = token.balanceOf(address(this));
        require(tokenBalance > 0, "No tokens to withdraw");

        // Emit event for paymentReceiver
        emit TokensWithdrawn(paymentReceiver, _token, tokenBalance);

        require(
            token.transfer(paymentReceiver, tokenBalance),
            "Token transfer failed for paymentReceiver"
        );
    }

    function _baseURI() internal view override returns (string memory) {
        return _baseTokenURI;
    }

    /**
     * @dev Allows the admin to update the base URI for token metadata.
     */
    function setBaseURI(string memory baseTokenURI) public onlyAdmin {
        _baseTokenURI = baseTokenURI;
    }

    /**
     * @dev Returns the token URI for a given token ID.
     */
    function tokenURI(
        uint256 tokenId
    ) public view override returns (string memory) {
        _requireOwned(tokenId);

        string memory baseURI = _baseURI();
        return
            bytes(baseURI).length > 0
                ? string.concat(baseURI, tokenId.toString(), ".json")
                : "";
    }

    /**
     * @dev Returns the native currency (ETH) balance of the contract.
     */
    function balanceOfContract() public view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @dev Returns the balance of a specified ERC20 token held by the contract.
     */
    function tokenBalanceOfContract(
        address tokenAddress
    ) public view returns (uint256) {
        require(
            autheoCentralStore.supportedTokens(tokenAddress) == true,
            "Unsupported token"
        );
        return IERC20(tokenAddress).balanceOf(address(this));
    }

    /**
     * @dev Returns the number of available nodes that can still be minted.
     */
    function availableNodes() public view returns (uint256) {
        return totalNodes - _nextTokenId;
    }

    /**
     * @dev Reverts if the caller is not an admin.
     */
    modifier onlyAdmin() {
        require(
            msg.sender == admin,
            "Unauthorized! Only admin can perform this operation"
        );
        _;
    }
}
