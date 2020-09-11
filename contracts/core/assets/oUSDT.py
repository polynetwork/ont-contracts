OntCversion = '2.0.0'
"""
oUSDT denotes the cross chain USDT asset on Ontology, which is same as USDT in Ethereum
"""
from ontology.interop.System.Storage import GetContext, Get, Put, Delete
from ontology.interop.System.Runtime import CheckWitness
from ontology.interop.System.Action import RegisterAction
from ontology.builtins import concat
from ontology.interop.Ontology.Runtime import Base58ToAddress

TransferEvent = RegisterAction("transfer", "from", "to", "amount")
ApprovalEvent = RegisterAction("approval", "owner", "spender", "amount")

ctx = GetContext()

NAME = 'oUSDT'
SYMBOL = 'oUSDT'
DECIMALS = 6
FACTOR = 1000000
Operator = Base58ToAddress("AQf4Mzu1YJrhz9f3aRkkwSm9n3qhXGSh4p")
CROSS_CHAIN_CONTRACT_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09')
BALANCE_PREFIX = bytearray(b'\x01')
APPROVE_PREFIX = bytearray(b'\x02')
SUPPLY_KEY = 'TotalSupply'

PROXY_HASH_KEY = "Proxy"


def Main(operation, args):
    """
    :param operation:
    :param args:
    :return:
    """
    if operation == 'init':
        return init()
    if operation == 'transferOwnership':
        return transferOwnership(args[0])
    if operation == 'getOwner':
        return getOwner()
    if operation == 'delegateToProxy':
        return delegateToProxy(args[0], args[1])
    if operation == 'name':
        return name()
    if operation == 'symbol':
        return symbol()
    if operation == 'decimals':
        return decimals()
    if operation == 'totalSupply':
        return totalSupply()
    if operation == 'balanceOf':
        assert (len(args) == 1)
        acct = args[0]
        return balanceOf(acct)
    if operation == 'transfer':
        assert (len(args) == 3)
        from_acct = args[0]
        to_acct = args[1]
        amount = args[2]
        return transfer(from_acct, to_acct, amount)
    if operation == 'transferMulti':
        return transferMulti(args)
    if operation == 'transferFrom':
        assert (len(args) == 4)
        spender = args[0]
        from_acct = args[1]
        to_acct = args[2]
        amount = args[3]
        return transferFrom(spender, from_acct, to_acct, amount)
    if operation == 'approve':
        assert (len(args) == 3)
        owner = args[0]
        spender = args[1]
        amount = args[2]
        return approve(owner, spender, amount)
    if operation == 'allowance':
        assert (len(args) == 2)
        owner = args[0]
        spender = args[1]
        return allowance(owner, spender)

    if operation == "getProxyHash":
        return getProxyHash()
    return False

def init():
    assert (CheckWitness(Operator))
    assert (len(getOwner()) == 0)
    Put(GetContext(), OWNER_KEY, Operator)
    return True

def transferOwnership(newOwner):
    oldOwner = getOwner()
    assert (CheckWitness(oldOwner))
    assert (len(newOwner) == 20 and newOwner != ZERO_ADDRESS)
    Put(GetContext(), OWNER_KEY, newOwner)
    TransferOwnershipEvent(oldOwner, newOwner)
    return True

def getOwner():
    return Get(GetContext(), OWNER_KEY)

def delegateToProxy(proxyReversedHash, amount):
    """
    initialize the contract, put some important info into the storage in the blockchain
    :return:
    """
    assert (CheckWitness(Operator))

    storedProxy = getProxyHash()
    if not storedProxy:
        Put(ctx, PROXY_HASH_KEY, proxyReversedHash)
    else:
        assert (proxyReversedHash == storedProxy)

    Put(ctx, concat(BALANCE_PREFIX, proxyReversedHash), balanceOf(proxyReversedHash) + amount)
    Put(ctx, SUPPLY_KEY, totalSupply() + amount)
    TransferEvent("", proxyReversedHash, amount)
    return True

def name():
    """
    :return: name of the token
    """
    return NAME


def symbol():
    """
    :return: symbol of the token
    """
    return SYMBOL


def decimals():
    """
    :return: the decimals of the token
    """
    return DECIMALS


def totalSupply():
    """
    :return: the total supply of the token
    """
    return Get(ctx, SUPPLY_KEY) + 0


def balanceOf(account):
    """
    :param account:
    :return: the token balance of account
    """
    assert (len(account) == 20)
    return Get(ctx, concat(BALANCE_PREFIX, account)) + 0


def transfer(from_acct, to_acct, amount):
    """
    Transfer amount of tokens from from_acct to to_acct
    :param from_acct: the account from which the amount of tokens will be transferred
    :param to_acct: the account to which the amount of tokens will be transferred
    :param amount: the amount of the tokens to be transferred, >= 0
    :return: True means success, False or raising exception means failure.
    """
    assert (len(to_acct) == 20)
    assert (len(from_acct) == 20)
    assert (CheckWitness(from_acct))
    assert (amount > 0)

    fromKey = concat(BALANCE_PREFIX, from_acct)
    fromBalance = Get(ctx, fromKey)

    assert (fromBalance >= amount)

    if amount == fromBalance:
        Delete(ctx, fromKey)
    else:
        Put(ctx, fromKey, fromBalance - amount)

    toKey = concat(BALANCE_PREFIX, to_acct)
    toBalance = Get(ctx, toKey)
    Put(ctx, toKey, toBalance + amount)

    TransferEvent(from_acct, to_acct, amount)

    return True


def transferMulti(args):
    """
    :param args: the parameter is an array, containing element like [from, to, amount]
    :return: True means success, False or raising exception means failure.
    """
    for p in args:
        assert (len(p) == 3)
        assert (transfer(p[0], p[1], p[2]))

        # return False is wrong since the previous transaction will be successful

    return True


def approve(owner, spender, amount):
    """
    owner allow spender to spend amount of token from owner account
    Note here, the amount should be less than the balance of owner right now.
    :param owner:
    :param spender:
    :param amount: amount>=0
    :return: True means success, False or raising exception means failure.
    """
    assert (len(owner) == 20)
    assert (len(spender) == 20)
    assert (CheckWitness(owner))
    assert (amount >= 0)

    key = concat(concat(APPROVE_PREFIX, owner), spender)
    Put(ctx, key, amount)

    ApprovalEvent(owner, spender, amount)

    return True


def transferFrom(spender, from_acct, to_acct, amount):
    """
    spender spends amount of tokens on the behalf of from_acct, spender makes a transaction of amount of tokens
    from from_acct to to_acct
    :param spender:
    :param from_acct:
    :param to_acct:
    :param amount:
    :return:
    """
    assert (len(to_acct) == 20)
    assert (len(from_acct) == 20)
    assert (len(spender) == 20)
    assert (amount >= 0)
    assert (CheckWitness(spender))

    fromKey = concat(BALANCE_PREFIX, from_acct)
    fromBalance = Get(ctx, fromKey)

    assert (fromBalance >= amount)

    approveKey = concat(concat(APPROVE_PREFIX, from_acct), spender)
    approvedAmount = Get(ctx, approveKey)
    toKey = concat(BALANCE_PREFIX, to_acct)

    assert (approvedAmount >= amount)

    if amount == approvedAmount:
        Delete(ctx, approveKey)
        Put(ctx, fromKey, fromBalance - amount)
    else:
        Put(ctx, approveKey, approvedAmount - amount)
        Put(ctx, fromKey, fromBalance - amount)

    toBalance = Get(ctx, toKey)
    Put(ctx, toKey, toBalance + amount)

    TransferEvent(from_acct, to_acct, amount)

    return True


def allowance(owner, spender):
    """
    check how many token the spender is allowed to spend from owner account
    :param owner: token owner
    :param spender:  token spender
    :return: the allowed amount of tokens
    """
    key = concat(concat(APPROVE_PREFIX, owner), spender)
    return Get(ctx, key) + 0


def getProxyHash():
    return Get(ctx, PROXY_HASH_KEY)