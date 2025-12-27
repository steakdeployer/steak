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

- **Immutable**: Upgrade authority has been renounced
- **No admin withdraw**: Contract has no function to pull user tokens
- **Verified on Solscan**: [View Contract](https://solscan.io/account/3e4dEo9W7dKa2J2YdG9ymYuVSRn9UHnHXo7XiRtbTgXE)

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
