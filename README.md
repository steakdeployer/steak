# STEAK - Token-2022 Staking Contract

Solana staking program for Token-2022 tokens with epoch-based reward distribution.

## Program ID

```
3e4dEo9W7dKa2J2YdG9ymYuVSRn9UHnHXo7XiRtbTgXE
```

## Features

- Stake Token-2022 tokens
- Epoch-based reward snapshots (anti-gaming)
- Permissionless epoch rolling
- Only users can unstake their own tokens

## Security

- **Immutable**: Upgrade authority has been renounced - [Verify on Solscan](https://solscan.io/account/3e4dEo9W7dKa2J2YdG9ymYuVSRn9UHnHXo7XiRtbTgXE) (shows `Authority: none`)
- **No admin withdraw**: The deployed contract has NO function to pull user tokens
- **Users control their funds**: Only stake owners can unstake their own tokens

### Note on Source Code

The `emergency_withdraw` function in `lib.rs` was written during development but **never deployed**. The program was made immutable before any version containing `emergency_withdraw` was deployed on-chain.

**Proof:**
1. Check Solscan - Program shows `Authority: none` (immutable since Dec 27, 2024)
2. The on-chain bytecode does not contain the emergency_withdraw instruction
3. Any attempt to call `emergency_withdraw` will fail with "unknown instruction"

The deployed program only contains the instructions listed below.

## Instructions

| Instruction | Description |
|-------------|-------------|
| `initialize_pool` | Create staking pool for a mint |
| `deposit_steak` | Stake tokens |
| `withdraw_steak` | Unstake tokens |
| `roll_epoch` | Advance to next epoch (permissionless) |
| `close_stake_record` | Close empty stake record |

## Build

```bash
anchor build
```

## License

MIT
