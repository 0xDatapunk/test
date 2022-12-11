// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "./lib/ReentrancyGuarded.sol";
import "./lib/EIP712.sol";
import "./lib/MerkleVerifier.sol";
import "./interfaces/IExchange.sol";
import "./interfaces/IPool.sol";
import "./interfaces/IExecutionDelegate.sol";
import "./interfaces/IPolicyManager.sol";
import "./interfaces/IMatchingPolicy.sol";
import {
  Side,
  SignatureVersion,
  AssetType,
  Fee,
  Order,
  Input,
  Execution
} from "./lib/OrderStructs.sol";

/**
 * @title Exchange
 * @dev Core exchange contract
 */
contract Exchange_ref {
    /**
     * @dev Bulk execute multiple matches
     * @param executions Potential buy/sell matches
     */
    function bulkExecute(Execution[] calldata executions)
        external
        payable
    {
        
        // REFERENCE
        uint256 executionsLength = executions.length;
        for (uint8 i=0; i < executionsLength; i++) {
            bytes memory data = abi.encodeWithSelector(this._execute.selector, executions[i].sell, executions[i].buy);
            (bool success,) = address(this).delegatecall(data);
        }
        
        // uint256 executionsLength = executions.length;
        // for (uint8 i = 0; i < executionsLength; i++) {
        //     assembly {
        //         let memPointer := mload(0x40)

        //         let order_location := calldataload(add(executions.offset, mul(i, 0x20)))
        //         let order_pointer := add(executions.offset, order_location)

        //         let size
        //         switch eq(add(i, 0x01), executionsLength)
        //         case 1 {
        //             size := sub(calldatasize(), order_pointer)
        //         }
        //         default {
        //             let next_order_location := calldataload(add(executions.offset, mul(add(i, 0x01), 0x20)))
        //             let next_order_pointer := add(executions.offset, next_order_location)
        //             size := sub(next_order_pointer, order_pointer)
        //         }

        //         mstore(memPointer, 0xe04d94ae00000000000000000000000000000000000000000000000000000000) // _execute
        //         calldatacopy(add(0x04, memPointer), order_pointer, size)
        //         // must be put in separate transaction to bypass failed executions
        //         // must be put in delegatecall to maintain the authorization from the caller
        //         let result := delegatecall(gas(), address(), memPointer, add(size, 0x04), 0, 0)
        //     }
        // }
    }

    function _execute(Input calldata sell, Input calldata buy)
        public
        payable returns (Input calldata, Input calldata) {
            return (sell, buy);
    }

    /**
     * @dev Verify the validity of oracle signature
     * @param orderHash hash of the order
     * @param signatureVersion signature version
     * @param extraSignature packed oracle signature
     * @param blockNumber block number used in oracle signature
     */
    function _validateOracleAuthorization(
        bytes32 orderHash,
        SignatureVersion signatureVersion,
        bytes calldata extraSignature,
        uint256 blockNumber
    ) public view returns (uint8 v, bytes32 r, bytes32 s) {
        if (signatureVersion == SignatureVersion.Single) {
            // assembly {
            //     v := calldataload(extraSignature.offset)
            //     r := calldataload(add(extraSignature.offset, 0x20))
            //     s := calldataload(add(extraSignature.offset, 0x40))
            // }
            (v, r, s) = abi.decode(extraSignature, (uint8, bytes32, bytes32));
        } else if (signatureVersion == SignatureVersion.Bulk) {
            /* If the signature was a bulk listing the merkle path must be unpacked before the oracle signature. */
            // assembly {
            //     v := calldataload(add(extraSignature.offset, 0x20))
            //     r := calldataload(add(extraSignature.offset, 0x40))
            //     s := calldataload(add(extraSignature.offset, 0x60))
            // }
            // uint8 _v; bytes32 _r; bytes32 _s;
            (bytes32[] memory merklePath, uint8 _v, bytes32 _r, bytes32 _s) = abi.decode(extraSignature, (bytes32[], uint8, bytes32, bytes32));
            v = _v; r = _r; s = _s;
        }

        return (v,r,s);
    }

}
