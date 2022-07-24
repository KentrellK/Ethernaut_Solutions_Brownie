from brownie import network, config, accounts, MockV3Aggregator, Contract
from web3 import Web3

FORKED_LOCAL_ENVIRONMENTS = ["mainnet-fork"]
LOCAL_BLOCKCHAIN_ENVIRONMENTS = ["development", "ganache-local"]

DECIMALS = 8
STARTING_PRICE = 200000000000


def get_account():
    if (
        network.show_active()
        in LOCAL_BLOCKCHAIN_ENVIRONMENTS
        # or network.show_active() in FORKED_LOCAL_ENVIRONMENTS
    ):
        return accounts[0]
    else:
        return accounts.add(config["wallets"]["from_key"])


def deploy_contract(ContractClass, className, localAccountIndex, localConstructorArgs):
    """This method is used for when the instance is either from address or deployed
    locally, depending on network
    """

    if (
        network.show_active() in LOCAL_BLOCKCHAIN_ENVIRONMENTS
    ):  # or network.show_active() in FORKED_LOCAL_ENVIRONMENTS:
        if len(localConstructorArgs) > 0:
            classInstance = ContractClass.deploy(
                *localConstructorArgs,
                {"from": accounts[localAccountIndex]},
                publish_source=False,
            )
        else:
            classInstance = ContractClass.deploy(
                {"from": accounts[localAccountIndex]}, publish_source=False
            )
    else:
        classInstanceAddress = config["networks"][network.show_active()][
            f"{className}_address"
        ]
        classInstance = Contract.from_abi(
            className, classInstanceAddress, ContractClass.abi
        )

    return classInstance
