from ontology.libont import byte2int, hexstring2bytes, hexstring2address, bytes2hexstring
from ontology.interop.Ontology.Native import Invoke
from ontology.interop.Ontology.Contract import Migrate
from ontology.interop.System.Action import RegisterAction
from ontology.interop.Ontology.Runtime import Base58ToAddress
from ontology.interop.System.Storage import Put, GetContext, Get, Delete
from ontology.interop.System.ExecutionEngine import GetExecutingScriptHash
from ontology.interop.System.Runtime import CheckWitness, Notify, Serialize, Deserialize
from ontology.builtins import concat, state
from ontology.libont import bytearray_reverse
from ontology.interop.System.App import RegisterAppCall, DynamicAppCall

ZERO_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
ONT_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
ONG_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
CROSS_CHAIN_CONTRACT_ADDRESS = bytearray(
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09')
CONTRACT_ADDRESS = GetExecutingScriptHash()
ctx = GetContext()

NAME = 'OEP4-Skip-LockProxy'
SYMBOL = 'OEP4SL'
DECIMALS = 18

PAUSED = 'p1'
INITIALIZED = "p2"
TOTAL_SUPPLY_KEY = 'p3'
SUPPLY_CONTROLLER_KEY = 'p4'
OWNER_KEY = 'p5'
BALANCE_KEY = 'p6'
APPROVE_KEY = 'p7'

ASSET_HASH = "Asset"

Owner = Base58ToAddress('AQf4Mzu1YJrhz9f3aRkkwSm9n3qhXGSh4p')

# Event
TransferEvent = RegisterAction("transfer", "from", "to", "amount")
ApproveEvent = RegisterAction("approve", "owner", "spender", "amount")
UnlockEvent = RegisterAction("unlock", "OEP-4 Address", "amount")
LockEvent = RegisterAction("lock", "to_chainId", "fromAddress", "toAddress", "amount")


def Main(operation, args):
    if operation == "init":
        return init()
    if operation == "bindAssetHash":
        assert (len(args) == 2)
        toChainId = args[0]
        toAssetHash = args[1]
        return bindAssetHash(toChainId, toAssetHash)
    if operation == "getAssetHash":
        assert (len(args) == 1)
        toChainId = args[0]
        return getAssetHash(toChainId)
    if operation == 'lock':
        to_chainId = args[0]
        from_address = args[1]
        to_address = args[2]
        amount = args[3]
        return lock(to_chainId, from_address, to_address, amount)

    if operation == 'transferOwnership':
        newOwner = args[0]
        return transferOwnership(newOwner)

    if operation == 'getOwner':
        return getOwner()

    if operation == 'pause':
        return pause()

    if operation == 'unpause':
        return unpause()

    if operation == 'isPaused':
        return isPaused()

    if operation == 'isInitialized':
        return isInitialized()

    if operation == "upgrade":
        code = args[0]
        return upgrade(code)

    if operation == 'name':
        return name()

    if operation == 'symbol':
        return symbol()

    if operation == 'decimals':
        return decimals()

    if operation == 'totalSupply':
        return totalSupply()

    if operation == 'balanceOf':
        acct = args[0]
        return balanceOf(acct)

    if operation == 'transfer':
        from_acct = args[0]
        to_acct = args[1]
        amount = args[2]
        return transfer(from_acct, to_acct, amount)

    if operation == 'transferMulti':
        return transferMulti(args)

    if operation == 'transferFrom':
        spender = args[0]
        from_acct = args[1]
        to_acct = args[2]
        amount = args[3]
        return transferFrom(spender, from_acct, to_acct, amount)

    if operation == 'approve':
        owner = args[0]
        spender = args[1]
        amount = args[2]
        return approve(owner, spender, amount)

    if operation == 'allowance':
        owner = args[0]
        spender = args[1]
        return allowance(owner, spender)

    if operation == 'unlock':
        return unlock(args[0], args[1], args[2])

   


def init():
    """
    Initialize smart contract.
    :return: True or raise exception.
    """
    assert (CheckWitness(Owner))
    assert (not isInitialized())

    Put(ctx, INITIALIZED, True)
    Put(ctx, TOTAL_SUPPLY_KEY, 1000000000000000000)
    Put(ctx, OWNER_KEY, Owner)
    Put(ctx, concat(BALANCE_KEY, Owner), 1000000000000000000)

    return True


def bindAssetHash(toChainId, toAssetHash):
    assert (CheckWitness(getOwner()))
    Put(GetContext(), concat(ASSET_HASH, toChainId), toAssetHash)
    Notify(["bindAssetHash", toChainId, toAssetHash])
    return True

def getAssetHash(toChainId):
    return Get(GetContext(), concat(ASSET_HASH, toChainId))


def lock(toChainId, fromAddress, toAddress, amount):
    """
    Decrease token supply from deducter address.
    :param amount: decreased token amount.
    :return:
    """
    fee = 0
    assert (amount >= 0)
    assert (CheckWitness(fromAddress))
    assert (not isPaused())
    # eth address format:0x673dfa9caf9145fdbef98e9d9874f36e63d8a5b4,length is 42
    assert (len(toAddress) != 0)

    Put(ctx, concat(BALANCE_KEY, fromAddress), Sub(balanceOf(fromAddress), amount))
    Put(ctx, TOTAL_SUPPLY_KEY, Sub(totalSupply(), amount))

    # construct args for proxy contract in target chain
    toAssetHash = getAssetHash(toChainId)
    argsList = [toAddress, amount]

    input_bytes = _serialzieArgs(argsList)
    param = state(toChainId, toAssetHash, "unlock", input_bytes)
    assert (Invoke(0, CROSS_CHAIN_CONTRACT_ADDRESS, "createCrossChainTx", param))
    LockEvent(toChainId, fromAddress, toAddress, amount)
    return True

def unlock(params, fromContractAddr, fromChainId):
    """
    :param params:
    :return:
    """
    assert (CheckWitness(CROSS_CHAIN_CONTRACT_ADDRESS))
    res = _deserialzieArgs(params)
    toAddress = res[0]
    value = res[1]
    assert(fromContractAddr == getAssetHash(fromChainId))

    assert (value >= 0)
    assert (isAddress(toAddress))

    Put(ctx, concat(BALANCE_KEY, toAddress), Add(balanceOf(toAddress), value))
    Put(ctx, TOTAL_SUPPLY_KEY, Add(totalSupply(), value))
    UnlockEvent(toAddress, value)
    return True


def _serialzieArgs(argsList):
    buff = None
    address = argsList[0]
    amount = argsList[1]
    buff = WriteVarBytes(address, buff)
    buff = WriteUint255(amount, buff)
    return buff

def _deserialzieArgs(buff):
    offset = 0
    res = NextVarBytes(buff, offset)
    toAddress = res[0]

    res = NextUint255(buff, res[1])
    amount = res[0]

    return [toAddress, amount]


def transferOwnership(newOwner):
    """
    transfer contract ownership from current owner to new owner account.
    :param newOwner: new smart contract owner.
    :return:True or raise exception.
    """
    assert (isAddress(newOwner))
    assert (CheckWitness(getOwner()))

    Put(ctx, OWNER_KEY, newOwner)
    return True


def getOwner():
    """
    Get contract owner.
    :return:smart contract owner.
    """
    return Get(ctx, OWNER_KEY)


def pause():
    """
    Set the smart contract to paused state, the token can not be transfered, approved.
    Just can invoke some get interface, like getOwner.
    :return:True or raise exception.
    """
    assert (CheckWitness(getOwner()))

    Put(ctx, PAUSED, True)
    return True


def unpause():
    """
    Resume the smart contract to normal state, all the function can be invoked.
    :return:True or raise exception.
    """
    assert (CheckWitness(getOwner()))

    Put(ctx, PAUSED, False)
    return True


def isPaused():
    """
    Confirm whether the contract is paused or not.
    :return: True or False
    """
    return Get(ctx, PAUSED)


def isInitialized():
    """
    Confir whether the contract is initialized or not.
    :return: True or False
    """
    return Get(ctx, INITIALIZED)


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
    return Get(ctx, TOTAL_SUPPLY_KEY)


def balanceOf(account):
    """
    :param account:
    :return: the token balance of account
    """
    return Get(ctx, concat(BALANCE_KEY, account))


def transfer(from_acct, to_acct, amount):
    """
    Transfer amount of tokens from from_acct to to_acct
    :param from_acct: the account from which the amount of tokens will be transferred
    :param to_acct: the account to which the amount of tokens will be transferred
    :param amount: the amount of the tokens to be transferred, >= 0
    :return: True means success, False or raising exception means failure.
    """
    assert (not isPaused())
    assert (amount > 0)
    assert (isAddress(to_acct))
    assert (CheckWitness(from_acct))

    fromKey = concat(BALANCE_KEY, from_acct)
    fromBalance = balanceOf(from_acct)
    if amount > fromBalance:
        return False
    if amount == fromBalance:
        Delete(ctx, fromKey)
    else:
        Put(ctx, fromKey, Sub(fromBalance, amount))

    toKey = concat(BALANCE_KEY, to_acct)
    toBalance = balanceOf(to_acct)
    Put(ctx, toKey, Add(toBalance, amount))

    TransferEvent(from_acct, to_acct, amount)

    return True


def transferMulti(args):
    """
    :param args: the parameter is 'transfer' function parameter array, like [from, to, amount]
    :return: True or raising exception.
    """
    for p in args:
        assert (len(p) == 3)
        assert (transfer(p[0], p[1], p[2]))

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
    assert (amount > 0)
    assert (not isPaused())
    assert (isAddress(spender))
    assert (CheckWitness(owner))
    assert (balanceOf(owner) >= amount)

    Put(ctx, concat(concat(APPROVE_KEY, owner), spender), amount)

    ApproveEvent(owner, spender, amount)

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
    assert (amount > 0)
    assert (not isPaused())
    assert (isAddress(from_acct) and isAddress(to_acct))
    assert (CheckWitness(spender))

    fromKey = concat(BALANCE_KEY, from_acct)
    fromBalance = balanceOf(from_acct)
    assert (fromBalance >= amount)

    approveKey = concat(concat(APPROVE_KEY, from_acct), spender)
    approvedAmount = Get(ctx, approveKey)

    if amount > approvedAmount:
        return False
    elif amount == approvedAmount:
        Delete(ctx, approveKey)
        Put(ctx, fromKey, Sub(fromBalance, amount))
    else:
        Put(ctx, approveKey, Sub(approvedAmount, amount))
        Put(ctx, fromKey, Sub(fromBalance, amount))

    toBalance = balanceOf(to_acct)
    Put(ctx, concat(BALANCE_KEY, to_acct), Add(toBalance, amount))

    TransferEvent(from_acct, to_acct, amount)

    return True


def allowance(owner, spender):
    """
    check how many token the spender is allowed to spend from owner account
    :param owner: token owner
    :param spender:  token spender
    :return: the allowed amount of tokens
    """
    key = concat(concat(APPROVE_KEY, owner), spender)
    return Get(ctx, key)


def upgrade(code):
    """
    upgrade current smart contract to new smart contract.
    :param code:new smart contract avm code.
    :return: True or raise exception.
    """
    owner = getOwner()
    assert (CheckWitness(owner))

    ongBalance = Invoke(0, ONG_ADDRESS, 'balanceOf', state(CONTRACT_ADDRESS))
    res = Invoke(0, ONG_ADDRESS, "transfer", [state(CONTRACT_ADDRESS, owner, ongBalance)])
    if res != b'\x01':
        assert (False)

    ontBalance = Invoke(0, ONT_ADDRESS, 'balanceOf', state(CONTRACT_ADDRESS))
    res = Invoke(0, ONT_ADDRESS, "transfer", [state(CONTRACT_ADDRESS, owner, ontBalance)])
    if res != b'\x01':
        assert (False)

    # upgrade smart contract
    res = Migrate(code, "", "", "", "", "", "")
    if not res:
        assert (False)

    Notify(["upgrade smart contract"])

    return True


def Add(a, b):
    """
    Adds two numbers, throws on overflow.
    :param a:operand a
    :param b:operand b
    :return:
	"""
    c = a + b
    assert (c >= a)
    return c


def Sub(a, b):
    """
    Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
    :param a: operand a
    :param b: operand b
    :return: a - b if a - b > 0 or revert the transaction.
    """
    assert (a >= b)
    return a - b


def isAddress(address):
    """
    check the address is legal address.
    :param address:
    :return:True or raise exception.
    """
    assert (len(address) == 20 and address != ZERO_ADDRESS)
    return True

def WriteBool(v, buff):
    if v == True:
        buff = concat(buff, b'\x01')
    elif v == False:
        buff = concat(buff, b'\x00')
    else:
        assert (False)
    return buff


def WriteByte(v, buff):
    assert (len(v) == 1)
    vBs = v[0:1]
    buff = concat(buff, vBs)
    return buff


def WriteUint8(v, buff):
    assert (v >= 0 and v <= 0xFF)
    buff = concat(buff, _convertNumToBytes(v, 1))
    return buff


def WriteUint16(v, buff):
    assert (v >= 0 and v <= 0xFFFF)
    buff = concat(buff, _convertNumToBytes(v, 2))
    return buff


def WriteUint32(v, buff):
    assert (v >= 0 and v <= 0xFFFFFFFF)
    buff = concat(buff, _convertNumToBytes(v, 4))
    return buff


def WriteUint64(v, buff):
    assert (v >= 0 and v <= 0xFFFFFFFFFFFFFFFF)
    buff = concat(buff, _convertNumToBytes(v, 8))
    return buff


def WriteUint255(v, buff):
    assert (v >= 0 and v <= 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    return WriteBytes(_convertNumToBytes(v, 32), buff)


def WriteVarUint(v, buff):
    if v < 0xFD:
        return WriteUint8(v, buff)
    elif v <= 0xFFFF:
        buff = concat(buff, 0xFD)
        return WriteUint16(v, buff)
    elif v <= 0xFFFFFFFF:
        buff = concat(buff, 0xFE)
        return WriteUint32(v, buff)
    else:
        buff = concat(buff, 0xFF)
        return WriteUint64(v, buff)


def WriteBytes(v, buff):
    return concat(buff, v)


def WriteVarBytes(v, buff):
    l = len(v)
    buff = WriteVarUint(l, buff)
    return WriteBytes(v, buff)


def WriteBytes20(v, buff):
    assert (len(v) == 20)
    return WriteBytes(v, buff)


def WriteBytes32(v, buff):
    assert (len(v) == 32)
    return WriteBytes(v, buff)


def WriteString(v, buff):
    return WriteVarBytes(v, buff)


def _convertNumToBytes(_val, bytesLen):
    l = len(_val)
    if l < bytesLen:
        for i in range(bytesLen - l):
            _val = concat(_val, b'\x00')
    if l > bytesLen:
        _val = _val[:bytesLen]
    return _val


def NextBool(buff, offset):
    if offset + 1 > len(buff):
        return [False, -1]
    val = buff[offset:offset + 1]
    if val == 1:
        return [True, offset + 1]
    elif val == 0:
        return [False, offset + 1]
    assert (False)


def NextByte(buff, offset):
    if offset + 1 > len(buff):
        return [0, -1]
    return [buff[offset:offset + 1], offset + 1]


def NextUint8(buff, offset):
    if offset + 1 > len(buff):
        return [0, -1]
    num = _convertBytesToNum(buff[offset:offset + 1])
    assert (num >= 0 and num <= 0xFF)
    return [num, offset + 1]


def NextUint16(buff, offset):
    if offset + 2 > len(buff):
        return [0, -1]
    num = _convertBytesToNum(buff[offset:offset + 2])
    assert (num >= 0 and num <= 0xFFFF)
    return [num, offset + 2]


def NextUint32(buff, offset):
    if offset + 4 > len(buff):
        return [0, -1]
    num = _convertBytesToNum(buff[offset:offset + 4])
    assert (num >= 0 and num <= 0xFFFFFFFF)
    return [num, offset + 4]


def NextUint64(buff, offset):
    if offset + 8 > len(buff):
        return [0, -1]
    num = _convertBytesToNum(buff[offset:offset + 8])
    assert (num >= 0 and num <= 0xFFFFFFFFFFFFFFFF)
    return [num, offset + 8]


def NextUint255(buff, offset):
    if offset + 32 > len(buff):
        return [0, -1]
    num = _convertBytesToNum(buff[offset:offset + 32])
    assert (num >= 0 and num <= 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    return [num, offset + 32]


def NextBytes(buff, offset, count):
    if offset + count > len(buff):
        return [0, -1]
    return [buff[offset:offset + count], offset + count]


def NextVarUint(buff, offset):
    res = NextByte(buff, offset)
    fb = res[0]
    offset = res[1]
    assert (res[1] > 0)
    # we can also use if concat(fb, b'\x00') == 0xfd:
    if fb == b'\xfd':
        return NextUint16(buff, offset)
    elif fb == b'\xfe':
        return NextUint32(buff, offset)
    elif fb == b'\xff':
        return NextUint64(buff, offset)
    else:
        return [fb, offset]


def NextVarBytes(buff, offset):
    res = NextVarUint(buff, offset)
    return NextBytes(buff, res[1], res[0])


def NextBytes20(buff, offset):
    if offset + 20 > len(buff):
        return [0, -1]
    return [buff[offset:offset + 20], offset + 20]


def NextBytes32(buff, offset):
    if offset + 32 > len(buff):
        return [0, -1]
    return [buff[offset:offset + 32], offset + 32]


def NextString(buff, offset):
    return NextVarBytes(buff, offset)


def _convertBytesToNum(_bs):
    firstNonZeroPostFromR2L = _getFirstNonZeroPosFromR2L(_bs)
    assert (firstNonZeroPostFromR2L >= 0)
    # in case the last byte of _bs is greater than 0x80,
    # we need to append a byte of zero to mark it as positive
    if firstNonZeroPostFromR2L > len(_bs):
        _bs = concat(_bs, b'\x00')
        # here we add this condition to limit the converted bytes has the maximum length of 32.
        # The reason is ontology can recognize a 33 byte as a number which can be greater than the 32 bytes length number
        assert (len(_bs) <= 32)
        return _bs
    else:
        return _bs[:firstNonZeroPostFromR2L]


def _getFirstNonZeroPosFromR2L(_bs):
    bytesLen = len(_bs)
    for i in range(bytesLen):
        byteI = _bs[bytesLen - i - 1:bytesLen - i]
        if byteI != b'\x00':
            # convert byte to int
            byteI = concat(byteI, b'\x00')
            if byteI >= 0x80:
                return bytesLen + 1 - i
            else:
                return bytesLen - i
    return -1