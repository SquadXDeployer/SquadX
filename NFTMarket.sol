/**
 *Submitted for verification at BscScan.com on 2022-05-31
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
    
    function _genMsg (uint256[] memory list,address  _address1,address  _address2) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked( list, _address1,_address2));
    }

    function _check(uint256[] memory list,address  _address1,address  _address2,uint256 nonce,bytes memory sig) internal view returns (bool) {
         if(!signEnable){
            return true;
        }
        require(signAddress == _recoverSigner(_genMsg(list,_address1,_address2),sig),"Sign: sign invalid");
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
        emit TransferERC20Token(tokenAddress,_value);
        return IERC20TokenInterface(tokenAddress).transfer(_owner, _value);
    }
}

abstract contract Service is Ownable{
    bool private  running;

    event StatusChange(
        bool  status
    );

    constructor() {
        running = true;
    }

    modifier whenRunning() {
        require(running, "Service: Service stopped");
        _;
    }

    function changeStatus(bool _status) external onlyOwner {
        running = _status;
        emit StatusChange(_status);
    }

    function getStatus() view public returns(bool){
        return running;
    }

}


interface IERC20TokenInterface {
    function totalSupply()  view external returns(uint256)  ;
    function balanceOf(address _owner) view external returns (uint256);
    function transfer(address _to, uint256 _value) external returns (bool);
    function transferFrom(address _from, address _to, uint256 _value)external returns (bool);
    function approve(address _spender, uint256 _value) external returns (bool);
    function allowance(address _owner, address _spender) external view returns (uint256);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

interface IERC721TokenInterface{
    event Transfer(address indexed from,address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner,address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner,address indexed operator, bool approved);
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

interface INFTMarket {
    function list(address _nftTokenAddress,uint256 _nftTokenId ,uint256 _priceInWei,uint256  _logId,string memory _remark,uint256 _nonce,bytes memory _sign) external returns(bool);
    function listLog(uint256 _logId) external view returns( address nftTokenAddress,uint256 nftTokenId ,uint256 priceInWei,address seller,string memory remark,uint256 time);

    function remove(address _nftTokenAddress,uint256 _nftTokenId,uint256 _logId,string memory _remark,uint256 _nonce,bytes memory _sign) external returns(bool);
    function removeLog(uint256 _logId) external view returns( address nftTokenAddress,uint256 nftTokenId ,address seller,string memory remark,uint256 time);

    function purchase(address _nftTokenAddress,uint256 _nftTokenId,uint256 _orderId,string memory _remark,uint256 _nonce,bytes memory _sign) payable external returns(bool);
    function buyLog(uint256 _orderId) view external returns(address seller,address nftTokenAddress,uint256 nftTokenId,uint256 priceInWei,uint256 feeInWei,address buyer,string memory remark,uint256 time);

    function buyItems(uint256 _orderId, address _seller,uint256 _itemId,uint256 _priceInWei,string memory _remark,uint256 _nonce,bytes memory _sign) payable external returns(bool);
    function buyItemsLog(uint256 _orderId) view external returns(address seller,address buyer,uint256 itemId, uint256 priceInWei,uint256 feeInWei,string memory remark,uint256 time);
   
    function search(address _nftTokenAddress,uint256 _nftTokenId ) view external returns(address seller,address nftTokenAddress,uint256 nftTokenId,uint256 priceInWei,uint256 time);

    event  List(address _nftTokenAddress,uint256 _nftTokenId ,address _seller,uint256 _priceInWei,uint256 indexed   _logId,string  _remark) ;
    event  Remove(address _nftTokenAddress,uint256 _nftTokenId ,address _seller,uint256 indexed   _logId );
    event  Purchase(address _seller,address _nftTokenAddress,uint256 _nftTokenId ,uint256 _priceInWei,uint256 _feeInWei,address _buyer,uint256 indexed   _orderId,string  _remark) ;
    event  BuyItems(address _seller,uint256 _priceInWei,uint256 _feeInWei,uint256 _itemId,address _buyer,uint256 indexed   _orderId,string  _remark) ;
    event SetExpireTime(uint256 _expireTime);
    event SetSignAddress(address _signAddress);
    event SetSignEnable(bool _signEnable);
    event SetNftHolder(address _nftHolder);
    event SetFeePoolAddress(address _feePoolAddress);
    event SetFeeRate(uint256 _feeRate);
}


contract Payment{
    uint256 private feeRate;
    address private feePoolAddress;

    function _setFeeRate(uint256 _feeRate)internal {
        feeRate = _feeRate;
    }

    function _setFeePoolAddress(address _feePoolAddress)internal {
        feePoolAddress = _feePoolAddress;
    }

    function getFeeRate() view external returns(uint256){
        return feeRate;
    }

    function getFeePoolAddress() view  external returns(address){
        return feePoolAddress;
    }

    function _payment(uint _price,address _seller) internal returns (uint256 feeInWei){        
        require(msg.value >=_price,"Payment:  Full payment is required");
        feeInWei = _price * feeRate / 10000;
        uint256 payAmout = _price -  feeInWei;
        assert((payAmout + feeInWei) == _price);
        payable(_seller).transfer(payAmout);
        payable(feePoolAddress).transfer(feeInWei);
        uint256 change = msg.value - _price;
        assert((change + _price) == msg.value);
        if(change >0){
            payable(msg.sender).transfer(change);
        }
    return 0;
    }
}

abstract contract NFTWarehouse{
    address private nftHolder;
    function _setNftHolder(address _nftHolder)internal {
        nftHolder = _nftHolder;
    }

    function _put(address nftTokenAddress,uint256 tokenId)internal {
        IERC721TokenInterface nftToken = IERC721TokenInterface(nftTokenAddress);
        require(nftToken.ownerOf(tokenId)==msg.sender,"nftWarehouse: caller is not the token owner");
        nftToken.safeTransferFrom(msg.sender,nftHolder,tokenId);
    }

    function _pull(address nftTokenAddress,uint256 tokenId,address to)internal {
        IERC721TokenInterface nftToken = IERC721TokenInterface(nftTokenAddress);
        require(nftToken.ownerOf(tokenId)==nftHolder,"nftWarehouse: not found!");
        nftToken.safeTransferFrom(nftHolder,to,tokenId);
    }

}

contract NFTMarketDomain{

    struct Goods{
        address seller;
        address nftTokenAddress;
        uint256 nftTokenId;
        uint priceInWei;
        bool inSale;
        uint256 time;
    }

    struct GoodsPutLog{
        address seller;
        address nftTokenAddress;
        uint256 nftTokenId;
        uint priceInWei;
        bool succeed;
        string remark;
        uint256 time;
    }

    struct GoodsPullLog{
        address seller;
        address nftTokenAddress;
        uint256 nftTokenId;
        bool succeed;
        string remark;
        uint256 time;
    }

    struct GoodOrder{
        address seller;
        address nftTokenAddress;
        uint256 nftTokenId;
        address buyer;
        uint256 priceInWei;
        uint256 feeInWei;
        string remark;
        bool succeed;
        uint256 time;
    }

    struct VirtualGoodOrder{
        address seller;
        address buyer;
        uint256 itemId;
        uint256 priceInWei;
        uint256 feeInWei;
        string remark;
        bool succeed;
        uint256 time;
    }

}

contract  NFTMarket is INFTMarket,NFTMarketDomain,NFTWarehouse,Payment,Service,Sign{

    mapping (uint256 =>  GoodsPutLog) private putLogs;
    mapping (uint256 =>  GoodsPullLog) private pullLogs;
    mapping (address =>  mapping(uint256=>Goods)) private goodses;
    mapping (uint256 =>  GoodOrder) private orders;
    mapping (uint256 =>  VirtualGoodOrder) private virtualOrders;
    mapping (uint256 =>  bool) private virtualItemSellHisory;
    address private nftTokenPoolAddress;

    function list(address _nftTokenAddress,uint256 _nftTokenId ,uint256 _priceInWei,uint256  _logId,string memory _remark,uint256 _nonce,bytes memory _sign) override whenRunning external returns(bool){
        require(_nftTokenAddress!=address(0),"NFTMarket: Invalid address.");
        uint256 [] memory _list = new uint256[](4);
        _list[0]=_logId;
        _list[1]=_nftTokenId;     
        _list[2]=_priceInWei;
        _list[3]=_nonce;       
        _check(_list,_nftTokenAddress,_msgSender(),_nonce,_sign);

        _put(_nftTokenAddress,_nftTokenId);
        require(_priceInWei>0,"NFTMarket: Price cannot be lower than 0");
        require(!putLogs[_logId].succeed,"NFTMarket:  Order already exists");
        putLogs[_logId] = GoodsPutLog(
            {
            seller:_msgSender(),
            nftTokenAddress: _nftTokenAddress,
            nftTokenId:_nftTokenId,
            priceInWei:_priceInWei,
            succeed:true,
            remark:_remark,
            time:block.timestamp
            });

        goodses[_nftTokenAddress][_nftTokenId] = Goods(
            {
            seller:_msgSender(),
            nftTokenAddress: _nftTokenAddress,
            nftTokenId:_nftTokenId,
            priceInWei:_priceInWei,
            inSale:true,
            time:block.timestamp
            });
        emit List(_nftTokenAddress,_nftTokenId,_msgSender(),_priceInWei,_logId,_remark);
        return true;
    }

    function listLog(uint256 _logId) external override view returns( address nftTokenAddress,uint256 nftTokenId ,uint256 priceInWei,address seller,string memory remark,uint256 time){
        GoodsPutLog memory log = putLogs[_logId];
        if(log.succeed){
            return (log.nftTokenAddress,log.nftTokenId,log.priceInWei,log.seller,log.remark,log.time);
        }
    }

    function remove(address _nftTokenAddress,uint256 _nftTokenId,uint256 _logId,string memory _remark,uint256 _nonce,bytes memory _sign) override external returns(bool){
        require(_nftTokenAddress!=address(0),"NFTMarket: Invalid address.");
        uint256 [] memory _list = new uint256[](3);
        _list[0]=_logId;
        _list[1]=_nftTokenId;     
        _list[2]=_nonce;       
        _check(_list,_nftTokenAddress,_msgSender(),_nonce,_sign);

        Goods memory goods = goodses[_nftTokenAddress][_nftTokenId];
        require(!pullLogs[_logId].succeed,"NFTMarket:  Order already exists");
        require(goods.inSale,"NFTMarket: goods not found!");
        require(goods.seller==_msgSender(),"NFTMarket: not origin owner!");
        _pull(_nftTokenAddress,_nftTokenId,_msgSender());
        delete goodses[_nftTokenAddress][_nftTokenId];
        pullLogs[_logId] = GoodsPullLog(
            {
            seller:_msgSender(),
            nftTokenAddress: _nftTokenAddress,
            nftTokenId:_nftTokenId,
            succeed:true,
            remark:_remark,
            time:block.timestamp
            });
        emit Remove(_nftTokenAddress,_nftTokenId,_msgSender(),_logId);
        return true;
    }

    function removeLog(uint256 _logId) external override view returns( address nftTokenAddress,uint256 nftTokenId,address seller,string memory remark,uint256 time ){
        GoodsPullLog memory log = pullLogs[_logId];
        if(log.succeed){
            return (log.nftTokenAddress,log.nftTokenId,log.seller,log.remark,log.time);
        }
    }

    function purchase(address _nftTokenAddress,uint256 _nftTokenId,uint256 _orderId,string memory _remark,uint256 _nonce,bytes memory _sign) payable whenRunning override external returns(bool){
        require(_nftTokenAddress!=address(0),"NFTMarket: Invalid address.");
        uint256 [] memory _list = new uint256[](3);
        _list[0]=_orderId;
        _list[1]=_nftTokenId;     
        _list[2]=_nonce;       
        _check(_list,_nftTokenAddress,_msgSender(),_nonce,_sign);

        Goods memory goods = goodses[_nftTokenAddress][_nftTokenId];
        require(goods.inSale,"NFTMarket: goods not found!");
        require(!orders[_orderId].succeed,"NFTMarket:  Order already exists");
        uint256 feeInWei =  _payment(goods.priceInWei,goods.seller);
        _pull(goods.nftTokenAddress,goods.nftTokenId,_msgSender());
        orders[_orderId] = GoodOrder(
            {
            seller:goods.seller,
            nftTokenAddress: goods.nftTokenAddress,
            nftTokenId:goods.nftTokenId,
            buyer:_msgSender(),
            priceInWei:goods.priceInWei,
            feeInWei:feeInWei,
            remark:_remark,
            succeed:true,
            time:block.timestamp
            });
        delete goodses[_nftTokenAddress][_nftTokenId];
        emit Purchase(goods.seller,goods.nftTokenAddress,goods.nftTokenId,goods.priceInWei,feeInWei,_msgSender(),_orderId,_remark);
        return true;
    }

    function buyLog(uint256 _orderId) view override external returns(address seller,address nftTokenAddress,uint256 nftTokenId,uint256 priceInWei,uint256 feeInWei,address buyer,string memory remark,uint256 time){
        GoodOrder memory order = orders[_orderId];
        if(order.succeed){
            return (order.seller,order.nftTokenAddress,order.nftTokenId,order.priceInWei,order.feeInWei,order.buyer,order.remark,order.time);
        }
    }

    function search(address _nftTokenAddress,uint256 _nftTokenId) view override external returns(address seller,address nftTokenAddress,uint256 nftTokenId,uint256 priceInWei,uint256 time){
        Goods memory goods = goodses[_nftTokenAddress][_nftTokenId];
        if(goods.inSale){
            return (goods.seller,goods.nftTokenAddress,goods.nftTokenId,goods.priceInWei,goods.time);
        }
    }

    function buyItems(uint256 _orderId,address _seller,uint256 _itemId,uint256 _priceInWei,string memory _remark,uint256 _nonce,bytes memory _sign) payable override whenRunning external returns(bool){
        require(_seller!=address(0),"NFTMarket: Invalid address.");
        uint256 [] memory _list = new uint256[](4);
        _list[0]=_orderId;
        _list[1]=_itemId;
        _list[2]=_priceInWei;     
        _list[3]=_nonce;       
        _check(_list,_seller,_msgSender(),_nonce,_sign);

        require(!virtualItemSellHisory[_itemId],"NFTMarket:  item not found!");
        require(!virtualOrders[_orderId].succeed,"NFTMarket:  Order already exists");
        uint256 feeInWei =  _payment(_priceInWei,_seller);
        virtualOrders[_orderId] = VirtualGoodOrder(
            {
            seller:_seller,
            buyer:_msgSender(),
            itemId:_itemId,
            priceInWei:_priceInWei,
            feeInWei:feeInWei,
            remark:_remark, 
            succeed:true,
            time:block.timestamp
            });
        virtualItemSellHisory[_itemId] = true;
        emit BuyItems(_seller,_priceInWei,feeInWei,_itemId,_msgSender(),_orderId,_remark);
        return true;
    }

    function buyItemsLog(uint256 _orderId) view override external returns(address seller,address buyer,uint256 itemId,uint256 priceInWei,uint256 feeInWei,string memory remark,uint256 time){
        VirtualGoodOrder memory order = virtualOrders[_orderId] ;
        if(order.succeed){
            return(order.seller,order.buyer,order.itemId,order.priceInWei,order.feeInWei,order.remark,order.time);
        }
    }

    function setFeeRate(uint256 _feeRate) public onlyOwner {
        emit SetFeeRate(_feeRate);
        _setFeeRate(_feeRate);
    }

    function setFeePoolAddress(address _feePoolAddress) public onlyOwner {
        require(_feePoolAddress!=address(0),"NFTMarket: Invalid address.");
        emit SetFeePoolAddress(_feePoolAddress);
        _setFeePoolAddress(_feePoolAddress);
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
       require(_bnbPoolAddress!=address(0),"NFT Market: Invalid address.");
       emit SetBnbPoolAddress(_bnbPoolAddress);
       _setBnbPoolAddress(_bnbPoolAddress);
    }
   
    
    function setNftHolder(address _nftHolder) public onlyOwner{
       require(_nftHolder!=address(0),"NFTMarket: Invalid address.");
       emit SetNftHolder(_nftHolder);
       _setNftHolder(_nftHolder);
    }

    constructor(uint256 _feeRate,address _feePoolAddress,address _nftTokenPoolAddress,bool signEnable_,address signAddress_,uint256 expireTime_)  {
         require(_feePoolAddress!=address(0),"NFTMarket: Invalid address.");
          require(_nftTokenPoolAddress!=address(0),"NFTMarket: Invalid address.");
           require(signAddress_!=address(0),"NFTMarket: Invalid address.");
       
        _setFeeRate(_feeRate);
        _setFeePoolAddress(_feePoolAddress);
        _setNftHolder(_nftTokenPoolAddress);
        _setSignEnable(signEnable_);
        _setSignAddress(signAddress_);
        _setExpireTime(expireTime_);
    }
}
