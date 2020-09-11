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
from ontology.libont import AddressFromVmCode


ZERO_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
ONT_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
ONG_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
CROSS_CHAIN_CONTRACT_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09')
CONTRACT_ADDRESS = GetExecutingScriptHash()
ctx = GetContext()

NAME = 'BTCX'
SYMBOL = 'BTCX'
DECIMALS = 8

TOTAL_SUPPLY_KEY = 'supply'
OWNER_KEY = 'owner'
BALANCE_KEY = 'balance'
APPROVE_KEY = 'approve'

CONTRACT_HASH = "contracthash"
REDEEM_SCRIPT_KEY = "redeem"
MINLIMIT_KEY = "limit"

BTC_ChainId = 1
ETH_ChainId = 2
ONT_ChainId = 3


Owner = Base58ToAddress('AdzZ2VKufdJWeB8t9a8biXoHbbMe2kZeyH')

# Event
TransferEvent = RegisterAction("transfer", "from", "to", "amount")
ApproveEvent = RegisterAction("approve", "owner", "spender", "amount")
UnlockEvent = RegisterAction("unlock", "toAssetHash", "toAddress", "amount")
LockEvent = RegisterAction("lock", "fromAssetHash", "toChainId", "toAssetHash", "fromAddress", "toAddress", "amount")
SetMinBackBTCEvent = RegisterAction("SetMinBackBTCEvent", "minimumCrossChainTransferLimit")

def Main(operation, args):
    if operation == "init":
        assert(len(args) == 2)
        redeemScript = args[0]
        scriptHash = args[1]
        return init(redeemScript, scriptHash)

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

    if operation == 'lock':
        toChainId = args[0]
        fromAddress = args[1]
        toAddress = args[2]
        amount = args[3]
        return lock(toChainId, fromAddress, toAddress, amount)

    if operation == 'transferOwnership':
        newOwner = args[0]
        return transferOwnership(newOwner)

    if operation == 'getOwner':
        return getOwner()


    if operation == 'isInitialized':
        return isInitialized()

    if operation == "upgrade":
        assert (len(args) == 7)
        return upgrade([0], args[1], args[2], args[3], args[4], args[5], args[6])

    if operation == "bindContractAddrWithChainId":
        toChainId = args[0]
        contractAddr = args[1]
        return bindContractAddrWithChainId(toChainId, contractAddr)
    if operation == "setMinBackBTCLimit":
        assert (len(args) == 1)
        return setMinBackBTCLimit(args[0])

    if operation == "getMinBackBTCLimit":
        return getMinBackBTCLimit()
    if operation == "getContractAddrWithChainId":
        toChainId = args[0]
        return getContractAddrWithChainId(toChainId)
    if operation == "getBtcRedeemScript":
        return getBtcRedeemScript()

def init(redeemScript, scriptHash):
    """
    Initialize smart contract, put the redeem script and the corresponding redeem key into storage, only the owner can invoke this method
    :return: True or raise exception.
    """
    assert (CheckWitness(Owner))
    assert (not getBtcRedeemScript())

    Put(ctx, OWNER_KEY, Owner)
    # the chainId of btc is 1
    assert (bindContractAddrWithChainId(1, scriptHash))

    Put(ctx, REDEEM_SCRIPT_KEY, redeemScript)
    return True

def getBtcRedeemScript():
    """
    :return: redeem script in hex format
    """
    return Get(ctx, REDEEM_SCRIPT_KEY)

def bindContractAddrWithChainId(toChainId, contractAddr):
    """
    only the owner can do bind operation, put the contract address into storage indexed by 'toChainId'
    say,  btc asset contract is btcx1 in Ethereum network, toChainId should be 2
    btc asset contract is btcx2 in Neo network, toChainId should be 4
    :param toChainId: the chainId of the blockchain, this parameter is in integer format
    :param contractAddr: the contract address of asset btc in toChainId blockchain, this parameter is in hex format
    :return:
    """
    # make sure only the owner can invoke this method
    assert (CheckWitness(getOwner()))
    # put contractAddr in storage indexed by toChainId
    Put(GetContext(), concat(CONTRACT_HASH, toChainId), contractAddr)
    Notify(["bindContractAddrWithChainId", toChainId, contractAddr])
    return True


def setMinBackBTCLimit(minBackBTCLimit):
    """
    only the owner can invoke this method, set the minimum cross chain transfer amount of btcx in order to cover the
    transaction fee in the utxo based blockchian. Otherwise, the transaction after broadcast in the toChainId blockchain
    may probably fails due to insufficient balance to pay the transaction fee.
    :param minimumTransferLimit:
    :return:
    """
    # make sure only the owner can invoke this method
    assert (CheckWitness(getOwner()))
    # check the condition that minimumTransferLimit is greater than 0, less than 2,100,000,000,000,000
    assert (minBackBTCLimit > 0 and minBackBTCLimit < 2100000000000000)
    # put the value into storage
    Put(ctx, MINLIMIT_KEY, minBackBTCLimit)
    # emit the event
    SetMinBackBTCEvent(minBackBTCLimit)
    return True

def getMinBackBTCLimit():
    """
    :return: return the minimum amount of btc when cross back to btc blockchain
    """
    return Get(ctx, MINLIMIT_KEY)

def getContractAddrWithChainId(toChainId):
    """
    return the asset contract hash of btc in 'toChainId' blockchain
    :param toChainId: this parameter is in integer format
    :return: the asset contract hash of btc in 'toChainId' blockchain, returned value is in hex format
    """
    return Get(GetContext(), concat(CONTRACT_HASH, toChainId))



def lock(toChainId, fromAddress, toAddress, amount):
    """
    decrease the btcx balance of 'fromAddress' in this contract, decrease the total supply.
    request cross chain transaction from Ontology network to the 'toChainId' blockchain by sending serialized parameter to
    Ontology Native contract method of 'createCrossChainTx'.
    :param toChainId: indicates which blockchain 'fromAddress' wants to do cross chain transaction, in integer format.
    :param fromAddress: indicates the requester of this crosschain transaction invocation, in Ontology address format
    :param toAddress: indicates the address that will receive btcx asset in the 'toChainId' blockchain, in hex format,
                    if 'toAddress' belongs to Ethereum, we take the ethereum address and remove the '0x' then pass it as bytearray to contract
                    if 'toAddress' belongs to BitCoin, we take the btc address and force formating it to bytes and take the hex of bytes then pass it as bytearray to contract
    :param amount: indicates how many btcx 'fromAddress' want to do cross chain transaction from Ontology to another chain, in integer format, should be >= minimum limit
    :return:
    """
    btcRedeemScriptBytes = getBtcRedeemScript()
    assert(len(btcRedeemScriptBytes) != 0)
    # When cross back to btc blockchain, make sure the amount is no less than zero, the minimum cross chain limit, if no setMinBackBTCLimit, by default is 0
    if toChainId == BTC_ChainId:
        assert (amount >= getMinBackBTCLimit())
        argsList = [toAddress, amount, btcRedeemScriptBytes]
    else:
        assert (amount >=0 and toChainId != ONT_ChainId)
        argsList = [toAddress, amount]
    # check signature of from account
    assert (CheckWitness(fromAddress))
    # make sure the toAddress is not empty, since toChainId can be BTC_chainId, ETH_chainId, NEO_chainId
    # it is hard for us to check if the toAddress is legal, so here just check if it's empty
    assert (len(toAddress) != 0)
    # update the btcx balance of the from account
    Put(ctx, concat(BALANCE_KEY, fromAddress), Sub(balanceOf(fromAddress), amount))
    # decrease the total supply of Btcx
    Put(ctx, TOTAL_SUPPLY_KEY, Sub(totalSupply(), amount))

    # serialize the to account, amount, and redeem script together


    inputArgs = _serialzieArgs(argsList)

    # construct the parameters and pass them to the native cross chain manager contract to request for cross chain transaction
    toAssetHash = getContractAddrWithChainId(toChainId)
    assert(len(toAssetHash) != 0)
    param = state(toChainId, toAssetHash, "unlock", inputArgs)
    assert (Invoke(0, CROSS_CHAIN_CONTRACT_ADDRESS, "createCrossChainTx", param))
    # emit the event
    LockEvent(CONTRACT_ADDRESS, fromAddress, toChainId, toAssetHash, toAddress, amount)
    return True


def unlock(params, fromContractAddr, fromChainId):
    """
    the method should only be accessable for the ontology cross chain manager native contract.
    the 'params' will be deserialized just as it was serialized at the other side indicated by 'fromChainId'.
    make sure the fromContractAddr is we previously bound address through 'bindContractAddrWithChainId()' method.
    then update the balance and total supply
    :param params:
    :param fromContractAddr:
    :param fromChainId:
    :return:
    """
    # make sure this method is being invoked by the ontology native cross chain manager contract
    assert (CheckWitness(CROSS_CHAIN_CONTRACT_ADDRESS))
    # deserialize the params, obtain the toAddress and value and check its legality
    res = _deserialzieArgs(params)
    toAddress = res[0]
    value = res[1]
    assert (value >= 0)
    assert (isAddress(toAddress))
    assert(len(fromContractAddr) != 0)
    assert(fromContractAddr == getContractAddrWithChainId(fromChainId))
    # update the balance of toAddress and total supply
    Put(ctx, concat(BALANCE_KEY, toAddress), Add(balanceOf(toAddress), value))
    Put(ctx, TOTAL_SUPPLY_KEY, Add(totalSupply(), value))
    # emit the event
    UnlockEvent(CONTRACT_ADDRESS, toAddress, value)
    return True


def _serialzieArgs(argsList):
    """
    :param argsList: [toAddress, amount, btcRedeemScript] or [toAddress, amount]
    the length of argsList will be 3 only if we want to cross back to BTC blockchain
    :return: serialized bytes
    """
    buff = None
    address = argsList[0]
    amount = argsList[1]
    buff = WriteVarBytes(address, buff)
    buff = WriteUint64(amount, buff)
    if len(argsList) == 3:
        btcRedeemScript = argsList[2]
        buff = WriteVarBytes(btcRedeemScript, buff)
    return buff



def _deserialzieArgs(buff):
    offset = 0
    res = NextVarBytes(buff, offset)
    toAddress = res[0]

    res = NextUint64(buff, res[1])
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


def isInitialized():
    return getBtcRedeemScript() != None

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
    return Get(ctx, TOTAL_SUPPLY_KEY) + 0


def balanceOf(account):
    """
    :param account:
    :return: the token balance of account
    """
    return Get(ctx, concat(BALANCE_KEY, account)) + 0


def transfer(from_acct, to_acct, amount):
    """
    Transfer amount of tokens from from_acct to to_acct
    :param from_acct: the account from which the amount of tokens will be transferred
    :param to_acct: the account to which the amount of tokens will be transferred
    :param amount: the amount of the tokens to be transferred, >= 0
    :return: True means success, False or raising exception means failure.
    """
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
    return Get(ctx, key) + 0


def upgrade(code, needStorage, name, version, author, email, description):
    """
    upgrade current smart contract to new smart contract.
    :param code:new smart contract avm code.
    :return: True or raise exception.
    """
    owner = getOwner()
    assert (CheckWitness(owner))

    ontBalance = _getSelfONTBalance()
    if ontBalance > 0:
        res = Invoke(0, ONT_ADDRESS, "transfer", [state(CONTRACT_ADDRESS, owner, ontBalance)])
        assert (res)

    assert (_tryUnboundOng())
    ongBalance = _getSelfOngBalance()
    if ongBalance > 0:
        res = Invoke(0, ONG_ADDRESS, "transfer", [state(CONTRACT_ADDRESS, owner, ongBalance)])
        assert (res)
    # upgrade smart contract
    res = Migrate(code, needStorage, name, version, author, email, description)
    if not res:
        assert (False)
    Notify(["upgrade", AddressFromVmCode(code)])
    return True


def getSelfONGBalance():
    return _getSelfOngBalance() + _getUnboundOngBalance()

def _getSelfONTBalance():
    return Invoke(0, ONT_ADDRESS, 'balanceOf', state(CONTRACT_ADDRESS))

def _getSelfOngBalance():
    return Invoke(0, ONG_ADDRESS, 'balanceOf', state(CONTRACT_ADDRESS))

def _getUnboundOngBalance():
    return Invoke(0, ONG_ADDRESS, 'allowance', state(ONT_ADDRESS, CONTRACT_ADDRESS))

def _tryUnboundOng():
    unboundOng = _getUnboundOngBalance()
    if unboundOng > 0:
        params = state(CONTRACT_ADDRESS, ONT_ADDRESS, CONTRACT_ADDRESS, _getUnboundOngBalance())
        return Invoke(0, ONG_ADDRESS, 'transferFrom', params)
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