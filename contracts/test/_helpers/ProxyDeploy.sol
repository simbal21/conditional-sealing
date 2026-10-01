// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title ProxyDeploy
/// @notice Test-only helper that deploys an upgradeable impl behind an ERC1967Proxy,
///         matching the production deploy pattern in `script/Deploy.s.sol`.
/// @dev Required because V3 impl contracts call `_disableInitializers()` in their
///      constructor (audit finding F-01), so `initialize()` can no longer be invoked
///      directly on a freshly-`new`-ed impl. Tests must run against the proxy.
library ProxyDeploy {
    /// @notice Deploy `impl` behind an ERC1967Proxy, invoking `initData` as the
    ///         atomic constructor-time initialization call.
    /// @param impl     Address of the already-deployed implementation contract.
    /// @param initData ABI-encoded `initialize(...)` calldata (use `abi.encodeCall`).
    /// @return proxy   Address of the deployed proxy (cast to the impl type by caller).
    function deployProxy(address impl, bytes memory initData) internal returns (address proxy) {
        proxy = address(new ERC1967Proxy(impl, initData));
    }
}
