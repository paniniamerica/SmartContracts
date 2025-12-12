// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface ILimitbreakAccountFreezer {
    function freezeAccountsForCollection(
        address collection,
        address[] calldata accountsToFreeze
    ) external;

    function unfreezeAccountsForCollection(
        address collection,
        address[] calldata accountsToUnfreeze
    ) external;
}
