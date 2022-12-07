OntCversion = '2.0.0'
"""
Smart contract for locking and unlocking cross chain asset between Ontology and other chains
"""
from ontology.interop.Ontology.Native import Invoke
from ontology.interop.Ontology.Contract import Migrate
from ontology.interop.System.Action import RegisterAction
from ontology.interop.Ontology.Runtime import Base58ToAddress
from ontology.interop.System.Storage import Put, GetContext, Get
from ontology.interop.System.ExecutionEngine import GetExecutingScriptHash
from ontology.interop.System.Runtime import CheckWitness, Notify, Serialize, Deserialize
from ontology.builtins import concat, state, append, remove
from ontology.libont import bytearray_reverse
from ontology.interop.System.App import DynamicAppCall
from ontology.libont import AddressFromVmCode
from ontology.interop.Ontology.Wasm import InvokeWasm

ZERO_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
ONT_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
ONG_ADDRESS = bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
CONTRACT_ADDRESS = GetExecutingScriptHash()

PROXY_HASH = "ProxyHash"
CCM_ADDRESS = "CCMAddress"
ASSET_HASH = "Asset"
OPERATOR_PREFIX = "Operator"

FROM_ASSET_LIST_KEY = "FromAssetList"

Operator = Base58ToAddress('AdzZ2VKufdJWeB8t9a8biXoHbbMe2kZeyH')

UnlockEvent = RegisterAction("unlock", "toAssetHash", "toAddress", "amount")
LockEvent = RegisterAction("lock", "fromAssetHash", "toChainId", "toAssetHash", "fromAddress", "toAddress", "amount")

SelfContractAddress = GetExecutingScriptHash()


def Main(operation, args):
    if operation == "init":
        return init()
    if operation == "setCCM":
        assert (len(args) == 1)
        CCMAddress = args[0]
        return setCCM(CCMAddress)
    if operation == "bindProxyHash":
        assert (len(args) == 2)
        toChainId = args[0]
        targetProxyHash = args[1]
        return bindProxyHash(toChainId, targetProxyHash)
    if operation == "bindAssetHash":
        assert (len(args) == 3)
        fromAssetHash = args[0]
        toChainId = args[1]
        toAssetHash = args[2]
        return bindAssetHash(fromAssetHash, toChainId, toAssetHash)
    if operation == "transferOperator":
        assert (len(args) == 1)
        newOperator = args[0]
        return transferOperator(newOperator)
    if operation == "getCCM":
        return getCCM()
    if operation == "getProxyHash":
        assert (len(args) == 1)
        toChainId = args[0]
        return getProxyHash(toChainId)
    if operation == "getAssetHash":
        assert (len(args) == 2)
        fromAssetHash = args[0]
        toChainId = args[1]
        return getAssetHash(fromAssetHash, toChainId)
    if operation == "lock":
        assert (len(args) == 5)
        fromAssetHash = args[0]
        fromAddress = args[1]
        toChainId = args[2]
        toAddress = args[3]
        amount = args[4]
        return lock(fromAssetHash, fromAddress, toChainId, toAddress, amount)
    if operation == "unlock":
        assert (len(args) == 3)
        params = args[0]
        fromContractAddr = args[1]
        fromChainId = args[2]
        return unlock(params, fromContractAddr, fromChainId)
    if operation == "getBalanceFor":
        return getBalanceFor(args[0])
    if operation == "removeFromAssetFromList":
        assert (len(args) == 1)
        index = args[0]
        return removeFromAssetFromList(index)
    if operation == "addFromAssetFromList":
        assert (len(args) == 1)
        fromAssetHash = args[0]
        return addFromAssetFromList(fromAssetHash)
    if operation == "getFromAssetHashList":
        return getFromAssetHashList()
    if operation == "upgrade":
        assert (len(args) == 7)
        code = args[0]
        needStorage = args[1]
        name = args[2]
        version = args[3]
        author = args[4]
        email = args[5]
        description = args[6]
        return upgrade(code, needStorage, name, version, author, email, description)

    return True

def init():
    assert(len(Get(GetContext(), OPERATOR_PREFIX)) == 0)
    Put(GetContext(), OPERATOR_PREFIX, Operator)
    return True
    
def setCCM(CCMAddress):
    assert (CheckWitness(Get(GetContext(), OPERATOR_PREFIX)))
    Put(GetContext(), CCM_ADDRESS, CCMAddress)
    Notify(["setCCM", CCMAddress])
    return True  

def bindProxyHash(toChainId, targetProxyHash):
    assert (CheckWitness(Get(GetContext(), OPERATOR_PREFIX)))
    Put(GetContext(), concat(PROXY_HASH, toChainId), targetProxyHash)
    Notify(["bindProxyHash", toChainId, targetProxyHash])
    return True


def bindAssetHash(fromAssetHash, toChainId, toAssetHash):
    assert (CheckWitness(Get(GetContext(), OPERATOR_PREFIX)))
    assert (_addFromAssetHash(fromAssetHash))
    Put(GetContext(), concat(ASSET_HASH, concat(fromAssetHash, toChainId)), toAssetHash)
    curBalance = getBalanceFor(fromAssetHash)
    Notify(["bindAssetHash", fromAssetHash, toChainId, toAssetHash, curBalance])
    return True

def transferOperator(newOperator):
    assert (CheckWitness(Get(GetContext(), OPERATOR_PREFIX)))
    Put(GetContext(), OPERATOR_PREFIX, newOperator)
    return True

def getCCM():
    return Get(GetContext(), CCM_ADDRESS)


def getProxyHash(toChainId):
    return Get(GetContext(), concat(PROXY_HASH, toChainId))


def getAssetHash(fromAssetHash, toChainId):
    return Get(GetContext(), concat(ASSET_HASH, concat(fromAssetHash, toChainId)))

def lock(fromAssetHash, fromAddress, toChainId, toAddress, amount):
    """
    Decrease token supply from deducter address.
    :param amount: decreased token amount.
    :return:
    """
    assert (amount >= 0)
    assert (CheckWitness(fromAddress))
    assert (len(toAddress) != 0)

    # transfer asset from fromAddress to lock proxy contract
    assert (_transferToContract(fromAssetHash, fromAddress, amount))

    # construct args for proxy contract in target chain
    toAssetHash = getAssetHash(fromAssetHash, toChainId)
    # make sure the toAssetHash is not empty
    assert(len(toAssetHash) != 0)

    argsList = [toAssetHash, toAddress, amount]
    # invoke the native cross chain manager contract to make transaction to target chain
    inputArgs = _serialzieArgs(argsList)

    toProxyHash = getProxyHash(toChainId)
    # make sure the toProxyHash is not empty
    assert (len(toProxyHash) != 0)

    buff = b'\x00'
    
    buff = WriteByte(b'\x10', buff)
    buff = WriteUint32(5, buff)
    
    buff = WriteByte(b'\x01', buff)
    buff = WriteUint32(len("crossChain"), buff)
    buff = WriteBytes("crossChain", buff)
    
    buff = WriteByte(b'\x04', buff)
    buff = WriteBytes(_intTobytes(toChainId,16), buff)
    
    buff = WriteByte(b'\x05', buff)
    buff = WriteBytes(toProxyHash, buff)
    
    buff = WriteByte(b'\x01', buff)
    buff = WriteUint32(len("unlock"), buff)
    buff = WriteBytes("unlock", buff)
    
    buff = WriteByte(b'\x00', buff)
    buff = WriteUint32(len(inputArgs), buff)
    buff = WriteBytes(inputArgs, buff)  
  
    assert (InvokeWasm(getCCM(), buff))

    LockEvent(fromAssetHash, fromAddress, toChainId, toAssetHash, toAddress, amount)
    return True


def unlock(params, fromContractAddr, fromChainId):
    """
    :param params:
    :return:
    """
    # check if this method is invoked by the native cross chain manager contract
    assert (CheckWitness(getCCM()))
    # parse the args bytes constructed in source chain proxy contract, passed by multi-chain
    res = _deserialzieArgs(params)
    toAssetHash = res[0]
    toAddress = res[1]
    value = res[2]
    # check the from proxy contract is our stored target chain proxy contract hash, so we can trust its args data
    assert (fromContractAddr == getProxyHash(fromChainId))
    assert (value >= 0)
    assert (isAddress(toAssetHash))
    assert (isAddress(toAddress))

    # transfer asset from lock proxy contract to toAddress
    assert (_transferFromContract(toAssetHash, toAddress, value))

    UnlockEvent(toAssetHash, toAddress, value)

    return True



def getBalanceFor(_assetAddress):
    if _assetAddress == ONG_ADDRESS or _assetAddress == ONT_ADDRESS:
        return Invoke(0, _assetAddress, "balanceOf", SelfContractAddress)
    else:
        return DynamicAppCall(_assetAddress, "balanceOf", [SelfContractAddress])


def removeFromAssetFromList(index):
    assert (CheckWitness(Get(GetContext(), OPERATOR_PREFIX)))
    fahListInfo = Get(GetContext(), FROM_ASSET_LIST_KEY)
    if not fahListInfo:
        return True
    fahList = Deserialize(fahListInfo)
    fahList.remove(index)
    Put(GetContext(), FROM_ASSET_LIST_KEY, Serialize(fahList))
    Notify(["removeFromAssetFromList", index])
    return True

def addFromAssetFromList(fromAssetHash):
    assert (CheckWitness(Get(GetContext(), OPERATOR_PREFIX)))
    fahListInfo = Get(GetContext(), FROM_ASSET_LIST_KEY)
    fahList = []
    if not fahListInfo:
        fahList.append(fromAssetHash)
    else:
        fahList = Deserialize(fahListInfo)
        fahList.append(fromAssetHash)
    Put(GetContext(), FROM_ASSET_LIST_KEY, Serialize(fahList))
    Notify(["addFromAssetFromList", fromAssetHash])
    return True

def getFromAssetHashList():
    fahListInfo = Get(GetContext(), FROM_ASSET_LIST_KEY)
    if not fahListInfo:
        return []
    return Deserialize(fahListInfo)

def _serialzieArgs(argsList):
    buff = None
    assetHash = argsList[0]
    address = argsList[1]
    amount = argsList[2]
    buff = WriteVarBytes(assetHash, buff)
    buff = WriteVarBytes(address, buff)
    buff = WriteUint255(amount, buff)
    return buff


def _deserialzieArgs(buff):
    offset = 0
    res = NextVarBytes(buff, offset)
    assetAddress = res[0]

    res = NextVarBytes(buff, res[1])
    toAddress = res[0]

    res = NextUint255(buff, res[1])
    amount = res[0]

    return [assetAddress, toAddress, amount]


def _transferFromContract(_tokenAddress, _to, _amount):
    if _tokenAddress == ONG_ADDRESS or _tokenAddress == ONT_ADDRESS:
        assert (_tranferNativeAsset(_tokenAddress, SelfContractAddress, _to, _amount))
    else:
        assert (_transferOPE4FromContract(_tokenAddress, _to, _amount))
    return True


def _transferToContract(_tokenAddress, _from, _amount):
    if _tokenAddress == ONG_ADDRESS or _tokenAddress == ONT_ADDRESS:
        assert (_tranferNativeAsset(_tokenAddress, _from, SelfContractAddress, _amount))
    else:
        assert (_transferOPE4ToContract(_tokenAddress, _from, _amount))
    return True


def _tranferNativeAsset(_nativeAssetAddress, _from, _to, _amount):
    param = state(_from, _to, _amount)
    res = Invoke(0, _nativeAssetAddress, 'transfer', [param])
    if res and res == b'\x01':
        return True
    else:
        return False


def _transferOPE4ToContract(_oep4ReversedAddress, _from, _amount):
    param = [SelfContractAddress, _from, SelfContractAddress, _amount]
    res = DynamicAppCall(_oep4ReversedAddress, "transferFrom", param)
    if res and res == b'\x01':
        return True
    else:
        return False


def _transferOPE4FromContract(_oep4ReversedAddress, _to, _amount):
    param = [SelfContractAddress, _to, _amount]
    res = DynamicAppCall(_oep4ReversedAddress, "transfer", param)
    if res and res == b'\x01':
        return True
    else:
        return False

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



def _addFromAssetHash(fromAssetHash):
    fahListInfo = Get(GetContext(), FROM_ASSET_LIST_KEY)
    fahList = []
    if len(fahListInfo) == 0:
        fahList = []
    else:
        fahList = Deserialize(fahListInfo)
    # check exist in current list
    if not _checkExistInList(fromAssetHash, fahList):
        # 1024 is the maximum length of an array supported in NeoVM
        if len(fahList) >= 1024:
            return False
        fahList.append(fromAssetHash)
        Put(GetContext(), FROM_ASSET_LIST_KEY, Serialize(fahList))
    return True

def _checkExistInList(e, l):
    for ele in l:
        if e == ele:
            return True
    return False


def upgrade(code, needStorage, name, version, author, email, description):
    """
    upgrade current smart contract to new smart contract.
    :param code:new smart contract avm code.
    :return: True or raise exception.
    """
    assert (CheckWitness(Get(GetContext(), OPERATOR_PREFIX)))
    newContractHash = AddressFromVmCode(code)
    newContractAddr = bytearray_reverse(newContractHash)
    ontBalance = _getSelfONTBalance()
    if ontBalance > 0:
        res = Invoke(0, ONT_ADDRESS, "transfer", [state(CONTRACT_ADDRESS, newContractAddr, ontBalance)])
        assert (res)

    assert (_tryUnboundOng())
    ongBalance = _getSelfOngBalance()
    if ongBalance > 0:
        res = Invoke(0, ONG_ADDRESS, "transfer", [state(CONTRACT_ADDRESS, newContractAddr, ongBalance)])
        assert (res)

    # transfer all the asset locked within lockproxy contract to the new contract
    fahListInfo = Get(GetContext(), FROM_ASSET_LIST_KEY)
    if len(fahListInfo) > 0:
        fahList = Deserialize(fahListInfo)
        for e in fahList:
            amount = getBalanceFor(e)
            if amount > 0:
                assert (_transferFromContract(e, newContractAddr, newContractAddr))

    # upgrade smart contract
    res = Migrate(code, needStorage, name, version, author, email, description)
    assert (res)

    Notify(["upgrade smart contract"])

    return True


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


def _intTobytes(i,length):
    l = len(i)
    if l >= length:
        return i
    return concat(i,_getXZeroes(length - l))


def _getXZeroes(n):
    if n == 0:
        return b''
    else:
        tmp = b'\x00'
        for i in range (0 , n -1):
            tmp = concat(tmp,b'\x00')
        return tmp


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
