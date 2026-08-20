package evm

// Arc testnet network profile (docs/SPEC-X402-ARC.md §A.1).
//
// Everything here is public Arc documentation. None of it is a secret and none
// of it may be overridden by an RPC response: the chain id in particular is
// configuration the operator asserts, never a value adopted from eth_chainId
// (§A.5.8).
const (
	// ArcTestnetChainID is the EIP-155 chain id of Arc testnet.
	ArcTestnetChainID uint64 = 5042002

	// ArcTestnetCAIP2 is the CAIP-2 network identifier used as the gate's
	// allowlist key.
	ArcTestnetCAIP2 = "eip155:5042002"

	// ArcTestnetExplorerTxPrefix renders a settled transaction for a human.
	ArcTestnetExplorerTxPrefix = "https://testnet.arcscan.app/tx/"

	// USDCFaucet issues Arc testnet USDC.
	USDCFaucet = "https://faucet.circle.com"

	// USDCDecimals is the decimal precision of USDC's ERC-20 view — the view
	// every bound amount in this profile is expressed in.
	//
	// USDC on Arc is ALSO the native gas asset, where the same funds are
	// counted with 18 decimals. The two views are one pool of money, and this
	// package never converts between them (§A.5.7).
	USDCDecimals uint8 = 6

	// ArcTestnetNetworkTag is this deployment's u8 allowlist tag for
	// ArcTestnetCAIP2. Tags are deployment configuration and are permanent once
	// assigned, because they are hashed into every binding (SPEC-X402 §4).
	// 1 and 2 are already spent on solana:devnet in this tree.
	ArcTestnetNetworkTag byte = 3
)

// USDCArcTestnet is the USDC ERC-20 interface on Arc testnet.
var USDCArcTestnet = MustParseAddress("0x3600000000000000000000000000000000000000")
