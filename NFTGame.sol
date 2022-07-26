/**
 *Submitted for verification at BscScan.com on 2022-05-11
*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract Sign {

    uint256 private  expireTime;
    address private  signAddress;
    bool private signEnable;
    
    function getExpireTime() public view returns(uint256){
        return expireTime;
    }

    function getSignAddress() public view returns(address){
        return signAddress;
    }

    function getSignEnable() public view returns(bool){
        return signEnable;
    }

    function _setExpireTime(uint256 _expireTime) internal {
        expireTime = _expireTime;
    }

    function _setSignAddress(address _signAddress) internal {
        signAddress = _signAddress;
    }

    function _setSignEnable(bool _signEnable) internal {
        signEnable = _signEnable;
    }
    
    function _genMsg (uint256[] memory list,address _address) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked( list, _address));
    }

    function _check(uint256[] memory list,address _address,uint256 nonce,bytes memory sig) internal view returns (bool) {
        if(!signEnable){
            return true;
        }
        require(signAddress == _recoverSigner(_genMsg(list,_address),sig),"Sign: sign invalid");
        uint256 _now =  block.timestamp;
        uint256 diff;
        if(_now >=nonce){
            diff = _now - nonce;
        }else{
            diff = nonce - _now;
        }
        require(diff<= expireTime ,"Sign: nonce invalid");
        return true;
    }

    function _splitSignature(bytes memory sig)   internal pure  returns ( uint8, bytes32, bytes32){
        require(sig.length == 65);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }

    function _recoverSigner(bytes32 message, bytes memory sig) internal  pure   returns (address)
    {
        uint8 v;
        bytes32 r;
        bytes32 s;

        (v, r, s) = _splitSignature(sig);

        return ecrecover(message, v, r, s);
    }
}


/*
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    
    event TransferERC20Token(
        address indexed tokenAddress,
        uint256 amount
    );


    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(
            newOwner != address(0),
            "Ownable: new owner is the zero address"
        );
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }

    function transferERC20Token(address tokenAddress, uint _value) public virtual onlyOwner returns (bool) {
        require(tokenAddress != address(0),"Ownable: tokenAddress is the zero address");
        emit TransferERC20Token(tokenAddress,_value);
        return IERC20TokenInterface(tokenAddress).transfer(_owner, _value);
    }
}


interface IERC20TokenInterface {
    function totalSupply()  view external returns(uint256)  ;
    function balanceOf(address _owner) view external returns (uint256);
    function transfer(address _to, uint256 _value) external returns (bool);
    function transferFrom(address _from, address _to, uint256 _value)external returns (bool);
    function approve(address _spender, uint256 _value) external returns (bool);
    function allowance(address _owner, address _spender) external view returns (uint256);
}

interface IERC721TokenInterface{
    function balanceOf(address owner) external view returns (uint256 balance);
    function ownerOf(uint256 tokenId) external view returns (address owner);
    function safeTransferFrom(address from,address to, uint256 tokenId ) external;
    function transferFrom(address from,address to,uint256 tokenId) external;
    function approve(address to, uint256 tokenId) external;
    function getApproved(uint256 tokenId)external  view  returns (address operator);
    function setApprovalForAll(address operator, bool _approved) external;
    function isApprovedForAll(address owner, address operator)  external  view  returns (bool);
}

interface IERC721TokenFactoryInterface{
    function mint(address _owner,uint256 tokenId) external ;
    function burn(uint256 tokenId) external;
}

interface INFTGame {
    function makeSpaceStation(uint256  _orderId, uint256 _stationId ,uint256 _price,string memory _remark,uint256 _nonce,bytes memory _sign) payable external returns(bool);
    function conquerPlanet(uint256 _orderId,uint256 _planetId,uint256[] memory  _stationIds ,string memory _remark,uint256 _nonce,bytes memory _sign) external returns(bool);   
    function receiveSpaceStation(uint256  _orderId,uint256 _stationId ,string memory _remark,uint256 _nonce,bytes memory _sign)  external returns(bool);

    function getMakeSpaceStationOrder(uint256  _orderId)view   external returns(address owner,uint256 stationId,uint256 price,uint256 time,string memory remark);
    function getConquerOrder(uint256 _orderId) view external returns (address owner,uint256 planetId, uint256 []  memory  stationIds,uint256 time,string memory remark);
    function getReceiveSpaceStationOrder(uint256  _orderId)view   external returns(address owner,uint256 stationId,uint256 time,string memory remark);
    
    event MakeSpaceStation(uint256 indexed orderId,address owner,uint256 stationId,uint256 price,string remark);
    event ReceiveSpaceStation(uint256 indexed orderId,address owner,uint256 stationId,string remark);
    event ConquerPlanet(uint256 indexed orderId,address owner ,uint256 planetId,uint256[]   stationIds,string remark);
}

contract   WhitelistManager{
    mapping (address => uint256) private whitelist;

    function _setWhitelists(address  []  memory addresses,uint256 amount) internal{
        require(addresses.length >0,"WhitelistManager: addresses can not empty.");
        for(uint32 i=0;i<addresses.length;i++){
            whitelist[addresses[i]]=amount;
        }
    }

    function amountOf(address owner) view public returns(uint256) {
        return whitelist[owner];
    }

    function _decreaseAmount(address owner) internal returns(bool){
        require(amountOf(owner)>0,"WhitelistManager: balance is not enough");
        whitelist[owner]=whitelist[owner] - 1;
        return true;
    }

}

contract Payment is WhitelistManager{
    address private _bnbPoolAddress;

    function _setBnbPoolAddress(address bnbPoolAddress)internal{
        _bnbPoolAddress = bnbPoolAddress;
    }

    function _bnbPayment(uint256 _price) internal returns (bool){
        if(_price==0){
            require(_decreaseAmount(msg.sender));
        }
        require(msg.value >=_price,"Payment:  Full payment is required");
        payable(_bnbPoolAddress).transfer(msg.value);
    return true;
    }

}

contract Domains{

    struct MakeOrder{
        address owner;
        uint256 stationId;
        uint256 price;
        uint256 time;
        string remark;
        bool succeed;
    }


    struct ConquerOrder{
        address owner;
        uint256 planetId;
        uint256 [] stationIds;
        uint256 time;
        string remark;
        bool succeed;
    }

    struct ReceiveOrder{
        address owner;
        uint256 stationId;
        uint256 time;
        string remark;
        bool succeed;
    }

}

contract  NFTGame is INFTGame,Payment,Domains,Ownable,Sign{

    address private _stationNFTAddress;
    address private _planetNFTAddress;
    
    mapping (uint256 => MakeOrder) private makeOrders;
    mapping (uint256 => ConquerOrder) private conquerOrders;
    mapping (uint256 => ReceiveOrder) private receiveOrders;
    
    event SetWhitelists(address [] addresses,uint256 amount);

    function setWhitelists(address  []  memory addresses,uint256 amount) onlyOwner external returns(bool){
        emit SetWhitelists(addresses,amount);
        _setWhitelists(addresses,amount);
        return true;
    }

    function makeSpaceStation(uint256  _orderId, uint256 _stationId ,uint256 _price,string memory _remark,uint256 _nonce,bytes memory _sign) payable external override  returns(bool){
        uint256 [] memory _list = new uint256[](4);
        _list[0]=_orderId;
        _list[1]=_stationId;
        _list[2]=_price;        
        _list[3]=_nonce;       
        _check(_list,_msgSender(),_nonce,_sign);
        require(!makeOrders[_orderId].succeed,"NFTGame: Order already exists");
        require(_bnbPayment(_price),"NFTGame: pay failed!");
        IERC721TokenFactoryInterface(_stationNFTAddress).mint(_msgSender(),_stationId);
        makeOrders[_orderId] = MakeOrder({
            owner:_msgSender(),
            stationId:_stationId,
            price:_price,
            time:block.timestamp,
            remark:_remark,
            succeed:true
        });
        emit MakeSpaceStation(_orderId,_msgSender(),_stationId,_price,_remark);
        return true;
    }

    function conquerPlanet(uint256 _orderId,uint256 _planetId,uint256[] memory  _stationIds ,string memory _remark,uint256 _nonce,bytes memory _sign) external override returns(bool){
        require(_stationIds.length >0,"NFTGame: _stationIds can not empty.");
        uint256 [] memory _list = new uint256[](3+_stationIds.length );
        _list[0]=_orderId;
        _list[1]=_planetId;
        for(uint256 i = 0;i<_stationIds.length;i++){
            _list[i+2]=_stationIds[i];
        }
        _list[_list.length - 1] = _nonce;
        _check(_list,_msgSender(),_nonce,_sign);
        require(!conquerOrders[_orderId].succeed,"NFTGame: Order already exists");
        for(uint i=0;i<_stationIds.length;i++){
            require(IERC721TokenInterface(_stationNFTAddress).ownerOf(_stationIds[i])==_msgSender(),"NFTGame: invalid station owner");
            IERC721TokenFactoryInterface(_stationNFTAddress).burn(_stationIds[i]);
        }
        IERC721TokenFactoryInterface(_planetNFTAddress).mint(_msgSender(),_planetId);
        conquerOrders[_orderId]=ConquerOrder({
            owner:_msgSender(),
            planetId:_planetId,
            stationIds:_stationIds,
            time:block.timestamp,
            remark:_remark,
            succeed:true
            });
        emit ConquerPlanet(_orderId,_msgSender(),_planetId,_stationIds,_remark); 
        return true;
    }

    function receiveSpaceStation(uint256  _orderId,uint256 _stationId ,string memory _remark,uint256 _nonce,bytes memory _sign) external override returns(bool){
        uint256 [] memory _list = new uint256[](3);
        _list[0]=_orderId;
        _list[1]=_stationId;     
        _list[2]=_nonce;       
        _check(_list,_msgSender(),_nonce,_sign);
        require(!receiveOrders[_orderId].succeed,"NFTGame: order already exists");
        IERC721TokenFactoryInterface(_stationNFTAddress).mint(_msgSender(),_stationId);
        receiveOrders[_orderId]=ReceiveOrder({
            owner:_msgSender(),
            stationId:_stationId,
            time:block.timestamp,
            remark:_remark,
            succeed:true
        });
        emit ReceiveSpaceStation(_orderId,_msgSender(),_stationId,_remark);
        return true;
    }

    function getMakeSpaceStationOrder(uint256  _orderId)view override   external returns(address owner,uint256 stationId,uint256 price,uint256 time,string memory remark){
        MakeOrder memory order = makeOrders[_orderId];
        if(order.succeed){
            return (order.owner,order.stationId,order.price,order.time,order.remark);
        }
    }

    function getConquerOrder(uint256 _orderId)view  override external returns (address owner,uint256 planetId, uint256 []  memory  stationIds,uint256 time,string memory remark){
        ConquerOrder memory order = conquerOrders[_orderId];
        if(order.succeed){
            return (order.owner,order.planetId,order.stationIds,order.time,order.remark);
        }
    }

    function getReceiveSpaceStationOrder(uint256  _orderId)view override  external returns(address owner,uint256 stationId,uint256 time,string memory remark){
        ReceiveOrder memory order = receiveOrders[_orderId];
        if(order.succeed){
            return (order.owner,order.stationId,order.time,order.remark);
        }
    }

    function setExpireTime(uint256 _expireTime) public onlyOwner {
        emit SetExpireTime(_expireTime);
        _setExpireTime(_expireTime);
    }

    function setSignAddress(address _signAddress) public onlyOwner{
       require(_signAddress!=address(0),"SIGN: Invalid address.");
       emit SetSignAddress(_signAddress);
       _setSignAddress(_signAddress);
    }

    function setSignEnable(bool _signEnable) public onlyOwner{
       emit SetSignEnable(_signEnable)
       _setSignEnable(_signEnable);
    }

    function setBnbPoolAddress(address _bnbPoolAddress) public onlyOwner{
       require(_bnbPoolAddress!=address(0),"NFT Game: Invalid address.");
       emit SetBnbPoolAddress(_bnbPoolAddress);
       _setBnbPoolAddress(_bnbPoolAddress);
    }
    
    event SetExpireTime(uint256 _expireTime);
    event SetSignAddress(address _signAddress);
    event SetSignEnable(bool _signEnable);
    event SetBnbPoolAddress(address _bnbPoolAddress);

    constructor(address planetNFTAddress_,address stationNFTAddress_ ,address bnbPoolAddress_,bool signEnable_,address signAddress_,uint256 expireTime_)  {
        require(planetNFTAddress_!=address(0),"NFT Game: Invalid address.");
        require(stationNFTAddress_!=address(0),"NFT Game: Invalid address.");
        require(bnbPoolAddress_!=address(0),"NFT Game: Invalid address.");
        require(signAddress_!=address(0),"NFT Game: Invalid address.");
        _setBnbPoolAddress(bnbPoolAddress_);
        _stationNFTAddress = stationNFTAddress_;
        _planetNFTAddress = planetNFTAddress_;
        _setSignEnable(signEnable_);
        _setSignAddress(signAddress_);
        _setExpireTime(expireTime_);
    }
}
