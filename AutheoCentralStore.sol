// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";

/**
 * @title AutheoCentralStore
 * @dev This contract manages referral systems, user holdings, and token pricing.
 *      It supports upgradability via the UUPS proxy pattern.
 * @author Shiv Sharma - Zeeve
 */
contract AutheoCentralStore is Initializable, UUPSUpgradeable {
    // Chainlink price feed for ETH/USD conversion
    AggregatorV3Interface public ethUsdPriceFeed;

    // Super admin address with highest privileges
    address public superAdmin;

    // Mapping to track admin status of addresses
    mapping(address => bool) public isAdmin;

    // Mapping from referral code to user address
    mapping(string => address) public referralCodeToAddress;

    // Mapping from user address to referral code
    mapping(address => string) public addressToReferralCode;

    // Mapping to track active referral codes
    mapping(string => bool) public isActiveReferral;

    // Mapping of user token holdings
    mapping(address => uint256) public userHoldings;

    // Maximum allowed holdings per user
    uint256 public perUserCap;

    // Mapping of blacklisted users
    mapping(address => bool) public isBlackListed;

    // Mapping of kyc for users
    mapping(address => bool) public isKYC;

    // Percentage commission for referred users
    uint256 public referredCommissionPercentage;

    // Percentage commission for referrers
    uint256 public referrerCommissionPercentage;

    // Mapping to store whitelisted tier-wise contracts
    mapping(address => bool) public whitelistedTierContracts;

    // Mapping of supported tokens to buy nodes
    mapping(address => bool) public supportedTokens;

    // Mapping for internal wallets which can purchase more licenses
    mapping(address => bool) public internalAccounts;

    // Maximum allowed holdings for internal accounts
    uint256 public internalWalletMaxHoldings;

    /**
     * @dev Events to notify about contract updates.
     */
    event SuperAdminUpdated(
        address indexed newSuperAdmin,
        address indexed oldSuperAdmin
    );

    event AdminUpdated(address indexed admin, bool isAdmin);

    event ReferralCodeGenerated(address indexed user, string referralCode);

    event ReferralCodeActivenessUpdated(string referralCode, bool isActive);

    event UserBlacklistedStatusUpdate(address indexed user, bool status);

    event UserKYCStatusUpdate(address indexed user, bool status);

    event InternalAccountsUpdate(address indexed account, bool status);

    event ReferredCommissionPercentageUpdated(
        uint256 newReferredCommissionPercentage
    );

    event ReferrerCommisionPercentageUpdated(
        uint256 newReferrerCommisionPercentage
    );

    event ContractWhitelisted(address indexed contractAddress);
    event ContractRemovedFromWhitelist(address indexed contractAddress);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract with necessary parameters.
     * @param _ethUsdPriceFeed Address of the Chainlink ETH/USD price feed.
     * @param _usdtContractAddress Address of the USDT token contract.
     * @param _usdcContractAddress Address of the USDC token contract.
     * @param _referredCommisionPercentage Commission percentage for referred users.
     * @param _referrerCommissionPercentage Commission percentage for referrers.
     * @param _perUserCap Maximum token holding per user.
     * @param _internalWalletMaxHoldings Maximum token holding for internal accounts.
     */
    function initialize(
        address _ethUsdPriceFeed,
        address _usdtContractAddress,
        address _usdcContractAddress,
        uint256 _referredCommisionPercentage,
        uint256 _referrerCommissionPercentage,
        uint256 _perUserCap,
        uint256 _internalWalletMaxHoldings
    ) public initializer {
        __UUPSUpgradeable_init();

        require(_ethUsdPriceFeed != address(0), "Not a valid address");
        require(_usdtContractAddress != address(0), "Not a valid address");
        require(_usdcContractAddress != address(0), "Not a valid address");

        superAdmin = msg.sender;
        isAdmin[msg.sender] = true;
        ethUsdPriceFeed = AggregatorV3Interface(_ethUsdPriceFeed);
        supportedTokens[_usdtContractAddress] = true;
        supportedTokens[_usdcContractAddress] = true;
        referredCommissionPercentage = _referredCommisionPercentage;
        referrerCommissionPercentage = _referrerCommissionPercentage;
        perUserCap = _perUserCap;
        internalWalletMaxHoldings = _internalWalletMaxHoldings;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlySuperAdmin {}

    /**
     * @dev Updates the super admin of the contract.
     * @param newSuperAdmin Address of the new super admin
     */
    function transferSuperAdmin(address newSuperAdmin) external onlySuperAdmin {
        require(newSuperAdmin != address(0), "Not a valid address");
        superAdmin = newSuperAdmin;

        emit SuperAdminUpdated(newSuperAdmin, msg.sender);
    }

    /**
     * @dev Updates the admin role for a given address.
     * @param admin Address to be updated
     * @param status Boolean indicating admin status
     */
    function updateAdminRole(
        address admin,
        bool status
    ) external onlySuperAdmin {
        require(admin != address(0), "Not a valid address");

        isAdmin[admin] = status;

        emit AdminUpdated(admin, status);
    }

    /**
     * @dev Generates a referral code for the caller.
     * @param referralCode The referral code string
     */
    function generateReferralCode(string memory referralCode) external {
        require(
            bytes(referralCode).length >= 6 && bytes(referralCode).length <= 10,
            "Invalid referral code"
        );

        require(
            isValidString(referralCode),
            "ReferralCode cannot contain spaces"
        );

        require(
            referralCodeToAddress[referralCode] == address(0),
            "Referral code already exist"
        );

        require(
            bytes(addressToReferralCode[msg.sender]).length == 0,
            "User already generated referral code"
        );

        require(isBlackListed[msg.sender] == false, "Blacklisted User");

        require(isKYC[msg.sender], "User kyc is not valid");

        referralCodeToAddress[referralCode] = msg.sender;

        addressToReferralCode[msg.sender] = referralCode;

        isActiveReferral[referralCode] = true;

        emit ReferralCodeGenerated(msg.sender, referralCode);
    }

    /**
     * @dev Updates the activeness status of a referral code.
     * @param referralCode The referral code to update
     * @param isActive The new status of the referral code
     */
    function updateUserReferralActiveness(
        string memory referralCode,
        bool isActive
    ) external onlyAdmin {
        require(
            referralCodeToAddress[referralCode] != address(0),
            "Referral code not exist"
        );

        isActiveReferral[referralCode] = isActive;

        emit ReferralCodeActivenessUpdated(referralCode, isActive);
    }

    /**
     * @dev Updates the blacklist status of a user.
     * @param userAddress The address of the user to update
     * @param status The new blacklist status (true for blacklisted, false for not)
     */
    function updateBlackListUser(
        address userAddress,
        bool status
    ) external onlyAdmin {
        require(userAddress != address(0), "Not a valid address");

        isBlackListed[userAddress] = status;

        emit UserBlacklistedStatusUpdate(userAddress, status);
    }

    /**
     * @dev Updates the kyc status of a user.
     * @param userAddress The address of the user to update
     * @param status The new kyc status (true for kycs, false for not)
     */
    function updateKYCStatus(
        address userAddress,
        bool status
    ) external onlyAdmin {
        require(userAddress != address(0), "Not a valid address");

        isKYC[userAddress] = status;

        emit UserKYCStatusUpdate(userAddress, status);
    }

    /**
     * @dev Add accounts in the internal account list.
     * @param accounts The list of accounts
     */
    function addInternalAccounts(
        address[] calldata accounts
    ) external onlyAdmin {
        require(accounts.length != 0, "Invalid length");
        for (uint256 i = 0; i < accounts.length; ++i) {
            address internalAccount = accounts[i];
            internalAccounts[internalAccount] = true;

            emit InternalAccountsUpdate(internalAccount, true);
        }
    }

    /**
     * @dev Remove accounts in the internal account list.
     * @param accounts The list of accounts
     */
    function removeInternalAccounts(
        address[] calldata accounts
    ) external onlyAdmin {
        require(accounts.length != 0, "Invalid length");
        for (uint256 i = 0; i < accounts.length; ++i) {
            address internalAccount = accounts[i];
            internalAccounts[internalAccount] = false;

            emit InternalAccountsUpdate(internalAccount, false);
        }
    }

    /**
     * @dev Update max token holding for internal account.
     * @param newLimit New max token holding limit for internal accounts
     */
    function updateInternalWalletMaxHoldings(
        uint256 newLimit
    ) external onlyAdmin {
        internalWalletMaxHoldings = newLimit;
    }

    /**
     * @dev Whitelists a list of contract addresses.
     * @param contractAddresses The list of contract addresses to whitelist
     */
    function whitelistContract(
        address[] calldata contractAddresses
    ) external onlyAdmin {
        require(contractAddresses.length != 0, "Invalid length");
        for (uint256 i = 0; i < contractAddresses.length; ++i) {
            address contractAddress = contractAddresses[i];
            require(isContract(contractAddress), "Not a contract address");
            whitelistedTierContracts[contractAddress] = true;

            emit ContractWhitelisted(contractAddress);
        }
    }

    /**
     * @dev Removes contract addresses from the whitelist.
     * @param contractAddresses The list of contract addresses to remove
     */
    function removeWhitelistedContract(
        address[] calldata contractAddresses
    ) external onlyAdmin {
        require(contractAddresses.length != 0, "Invalid length");
        for (uint256 i = 0; i < contractAddresses.length; ++i) {
            address contractAddress = contractAddresses[i];
            require(
                whitelistedTierContracts[contractAddress],
                "Contract not whitelisted"
            );
            whitelistedTierContracts[contractAddress] = false;

            emit ContractRemovedFromWhitelist(contractAddress);
        }
    }

    /**
     * @dev Updates the holdings of a user.
     * @param user The address of the user
     * @param quantity The amount to add to the user's holdings
     */
    function updateHoldings(
        address user,
        uint256 quantity
    ) external onlyTierContract {
        require(user != address(0), "Not a valid address");

        userHoldings[user] += quantity;
    }

    /**
     * @dev  Updates the commission percentage for referred users.
     * @param newReferredCommissionPercentage The new commission percentage
     */
    function updateReferredCommissionPercentage(
        uint256 newReferredCommissionPercentage
    ) external onlyAdmin {
        referredCommissionPercentage = newReferredCommissionPercentage;

        emit ReferredCommissionPercentageUpdated(
            newReferredCommissionPercentage
        );
    }

    /**
     * @dev  Updates the commission percentage for referrers.
     * @param newReferrerCommisionPercentage The new commission percentage
     */
    function updateReferrerCommisionPercentage(
        uint256 newReferrerCommisionPercentage
    ) external onlyAdmin {
        referrerCommissionPercentage = newReferrerCommisionPercentage;

        emit ReferrerCommisionPercentageUpdated(newReferrerCommisionPercentage);
    }

    /**
     * @dev Check the provided address is a contract address or wallet address.
     */
    function isContract(address _addr) public view returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }

    /**
     * @dev Returns the string validation status.
     * @param input Provided string.
     * Check that provided string contains the spaces or not.
     */
    function isValidString(string memory input) internal pure returns (bool) {
        bytes memory inputBytes = bytes(input);
        for (uint256 i = 0; i < inputBytes.length; i++) {
            if (inputBytes[i] == 0x20) {
                // ASCII code for space is 0x20
                return false;
            }
        }
        return true;
    }

    /**
     * Returns the latest ETH price in USD (with 8 decimals).
     */
    function getLatestEthPriceInUsd() public view returns (int) {
        (
            ,
            // roundId
            int price, // answeredInRound
            ,
            ,

        ) = ethUsdPriceFeed.latestRoundData();
        return price;
    }

    /**
     * Returns the latest USD price in terms of ETH (with 18 decimals).
     */
    function getUsdPriceInEth() public view returns (uint) {
        int ethPriceInUsd = getLatestEthPriceInUsd();
        require(ethPriceInUsd > 0, "Invalid ETH price from oracle");

        // 1e26 used for precision adjustment (18 decimals for ETH and 8 decimals for price feed)
        return uint(1e26) / uint(ethPriceInUsd);
    }

    /**
     * @dev Returns the current contract version.
     */
    function getContractVersion() public pure returns (string memory) {
        return "0.0.1";
    }

    /**
     * @dev Reverts if the caller is not the super admin.
     */
    modifier onlySuperAdmin() {
        require(
            msg.sender == superAdmin,
            "Unauthorized! Only super admin can perform this operation"
        );
        _;
    }

    /**
     * @dev Reverts if the caller is not an admin.
     */
    modifier onlyAdmin() {
        require(
            isAdmin[msg.sender] == true,
            "Unauthorized! Only admin can perform this operation"
        );
        _;
    }

    /**
     * @dev Reverts if the caller is not a whitelisted tier contract.
     */
    modifier onlyTierContract() {
        require(
            whitelistedTierContracts[msg.sender] == true,
            "Only tier contract can perform this operation"
        );
        _;
    }
}
