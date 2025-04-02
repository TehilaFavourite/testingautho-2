// SPDX-License-Identifier: MIT
// Compatible with OpenZeppelin Contracts ^5.0.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract USDCToken is ERC20 {
    constructor() ERC20("USDCToken", "USDC") {
        _mint(msg.sender, 10000000000000000000000000000);
    }

    function decimals() public view virtual override returns (uint8) {
        return 6;
    }

    function mint(uint256 amount) public {
        require(amount > 0, "Amount is 0");
        require(amount < 100000, "Amount is too high");
        _mint(msg.sender, amount * 10 ** 6);
    }
}