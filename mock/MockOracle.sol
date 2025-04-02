// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import "@chainlink/contracts/src/v0.8/tests/MockV3Aggregator.sol";

contract MockOracle is MockV3Aggregator {
    constructor() MockV3Aggregator(8, 375842930000) {}
}
