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
- **No admin withdraw**: The contract has NO function to pull user tokens
- **Users control their funds**: Only stake owners can unstake their own tokens

### Transparency Note

During development, an `emergency_withdraw` function was written but **never deployed**. The program was made immutable (Dec 27, 2024) before that code was ever deployed on-chain. The source code in this repository reflects the actual deployed contract - no admin withdrawal capability exists.

**Verify:**
- Solscan shows `Authority: none` (immutable)
- The on-chain program matches this source code

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
