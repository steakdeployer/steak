use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token_interface::{
        transfer_checked, Mint, TokenAccount, TokenInterface, TransferChecked,
    },
};
use spl_token_2022::{
    extension::{BaseStateWithExtensions, StateWithExtensions},
    state::Mint as MintState,
};

declare_id!("3e4dEo9W7dKa2J2YdG9ymYuVSRn9UHnHXo7XiRtbTgXE");

/// Token-2022 program ID
pub const TOKEN_2022_PROGRAM_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// ============================================================================
/// ADMIN WALLET - Only this wallet can initialize pools
/// Set this to your MEAT wallet address before deploying
/// ============================================================================
pub const ADMIN: Pubkey = pubkey!("GHVezVbLz1yvA3ZXSLaRqxyzgn45uSYR3Goj8wcZAnUf"); // MAINNET admin wallet

/// Minimum stake amount (1 token with 6 decimals = 1_000_000)
/// Prevents spam attacks with dust amounts
pub const MIN_STAKE_AMOUNT: u64 = 1_000_000;

#[program]
pub mod steak {
    use super::*;

    /// Initialize a new staking pool for any Token-2022 mint.
    /// Only the ADMIN wallet can initialize pools (prevents random pool creation).
    /// The mint is stored in the pool and validated for extensions.
    pub fn initialize_pool(ctx: Context<InitializeGrill>, epoch_length_slots: u64) -> Result<()> {
        // Only admin can initialize pools
        require_keys_eq!(
            ctx.accounts.admin.key(),
            ADMIN,
            SteakError::Unauthorized
        );

        // Validate token program is Token-2022
        require_keys_eq!(
            ctx.accounts.token_program.key(),
            TOKEN_2022_PROGRAM_ID,
            SteakError::InvalidTokenProgram
        );

        // Validate mint has no problematic extensions (TransferFee, TransferHook)
        validate_mint_extensions(&ctx.accounts.mint.to_account_info())?;

        let clock = Clock::get()?;
        let pool = &mut ctx.accounts.pool;

        pool.admin = ctx.accounts.admin.key();
        pool.mint = ctx.accounts.mint.key();
        pool.vault_ata = ctx.accounts.vault_ata.key();
        pool.total_staked = 0;
        pool.epoch = 0;
        pool.epoch_start_slot = clock.slot;
        pool.epoch_length_slots = epoch_length_slots;
        pool.bump = ctx.bumps.pool;

        emit!(PoolInitializedEvent {
            pool: pool.key(),
            admin: pool.admin,
            mint: pool.mint,
            epoch_length_slots,
            slot: clock.slot,
        });

        Ok(())
    }

    /// Stake tokens into the pool (put your steak on the grill!)
    pub fn deposit_steak(ctx: Context<DepositSteak>, amount: u64) -> Result<()> {
        require!(amount > 0, SteakError::InvalidAmount);
        require!(amount >= MIN_STAKE_AMOUNT, SteakError::StakeTooSmall);

        let clock = Clock::get()?;
        let pool = &mut ctx.accounts.pool;
        let stake_record = &mut ctx.accounts.stake_record;

        // Transfer tokens from user to vault
        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.user_ata.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.vault_ata.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount,
            ctx.accounts.mint.decimals,
        )?;

        // Update stake record
        stake_record.owner = ctx.accounts.user.key();
        stake_record.pool = pool.key();
        stake_record.amount = stake_record
            .amount
            .checked_add(amount)
            .ok_or(SteakError::MathOverflow)?;
        stake_record.last_stake_epoch = pool.epoch;
        stake_record.last_update_slot = clock.slot;
        stake_record.bump = ctx.bumps.stake_record;

        // Update pool total
        pool.total_staked = pool
            .total_staked
            .checked_add(amount)
            .ok_or(SteakError::MathOverflow)?;

        emit!(StakeEvent {
            pool: pool.key(),
            user: ctx.accounts.user.key(),
            amount,
            new_user_amount: stake_record.amount,
            new_total: pool.total_staked,
            epoch: pool.epoch,
            slot: clock.slot,
        });

        Ok(())
    }

    /// Unstake tokens from the pool (take your steak off the grill!)
    pub fn withdraw_steak(ctx: Context<WithdrawSteak>, amount: u64) -> Result<()> {
        require!(amount > 0, SteakError::InvalidAmount);

        let clock = Clock::get()?;
        let pool = &mut ctx.accounts.pool;
        let stake_record = &mut ctx.accounts.stake_record;

        // Check sufficient balance
        require!(
            stake_record.amount >= amount,
            SteakError::InsufficientStake
        );

        // Update accounting FIRST (before transfer)
        stake_record.amount = stake_record
            .amount
            .checked_sub(amount)
            .ok_or(SteakError::MathOverflow)?;
        stake_record.last_stake_epoch = pool.epoch;
        stake_record.last_update_slot = clock.slot;

        pool.total_staked = pool
            .total_staked
            .checked_sub(amount)
            .ok_or(SteakError::MathOverflow)?;

        // Transfer tokens from vault to user (PDA signs)
        let mint_key = pool.mint;
        let seeds = &[b"pool", mint_key.as_ref(), &[pool.bump]];
        let signer_seeds = &[&seeds[..]];

        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.vault_ata.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.user_ata.to_account_info(),
                    authority: pool.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
            ctx.accounts.mint.decimals,
        )?;

        emit!(UnstakeEvent {
            pool: pool.key(),
            user: ctx.accounts.user.key(),
            amount,
            new_user_amount: stake_record.amount,
            new_total: pool.total_staked,
            epoch: pool.epoch,
            slot: clock.slot,
        });

        Ok(())
    }

    /// Roll the epoch forward. Permissionless - anyone can flip the steaks!
    pub fn roll_epoch(ctx: Context<RollEpoch>) -> Result<()> {
        let clock = Clock::get()?;
        let pool = &mut ctx.accounts.pool;

        let elapsed = clock
            .slot
            .checked_sub(pool.epoch_start_slot)
            .ok_or(SteakError::MathOverflow)?;

        require!(
            elapsed >= pool.epoch_length_slots,
            SteakError::EpochNotReady
        );

        // Snapshot slot is the current slot (boundary)
        let snapshot_slot = clock.slot;

        pool.epoch = pool
            .epoch
            .checked_add(1)
            .ok_or(SteakError::MathOverflow)?;
        pool.epoch_start_slot = snapshot_slot;

        emit!(EpochRolledEvent {
            pool: pool.key(),
            new_epoch: pool.epoch,
            snapshot_slot,
        });

        Ok(())
    }

    /// Update the epoch length. Admin only - adjust the grill timer!
    pub fn update_epoch_length(ctx: Context<UpdateEpochLength>, new_epoch_length_slots: u64) -> Result<()> {
        let clock = Clock::get()?;
        let pool = &mut ctx.accounts.pool;
        let old_length = pool.epoch_length_slots;

        pool.epoch_length_slots = new_epoch_length_slots;

        emit!(EpochLengthUpdatedEvent {
            pool: pool.key(),
            old_length,
            new_length: new_epoch_length_slots,
            slot: clock.slot,
        });

        Ok(())
    }

    /// Close a stake record when amount is 0. User reclaims rent.
    pub fn close_stake_record(ctx: Context<CloseStakeRecord>) -> Result<()> {
        require!(
            ctx.accounts.stake_record.amount == 0,
            SteakError::StakeRecordNotEmpty
        );
        // Account will be closed via close constraint
        Ok(())
    }

    /// Close the pool. Admin only. Requires vault to be empty - shut down the grill!
    pub fn close_pool(ctx: Context<CloseGrill>) -> Result<()> {
        require!(
            ctx.accounts.pool.total_staked == 0,
            SteakError::PoolNotEmpty
        );
        require!(
            ctx.accounts.vault_ata.amount == 0,
            SteakError::VaultNotEmpty
        );
        // Account will be closed via close constraint
        Ok(())
    }

}

/// Validates that the mint has no TransferFee or TransferHook extensions
fn validate_mint_extensions(mint_account: &AccountInfo) -> Result<()> {
    let mint_data = mint_account.try_borrow_data()?;
    let mint_state = StateWithExtensions::<MintState>::unpack(&mint_data)
        .map_err(|_| SteakError::InvalidMint)?;

    // Check for TransferFeeConfig extension
    if mint_state
        .get_extension::<spl_token_2022::extension::transfer_fee::TransferFeeConfig>()
        .is_ok()
    {
        return Err(SteakError::UnsupportedMintExtension.into());
    }

    // Check for TransferHook extension
    if mint_state
        .get_extension::<spl_token_2022::extension::transfer_hook::TransferHook>()
        .is_ok()
    {
        return Err(SteakError::UnsupportedMintExtension.into());
    }

    Ok(())
}

// ============================================================================
// ACCOUNTS
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct Pool {
    /// Admin who can update settings (the grill master)
    pub admin: Pubkey,
    /// The Token-2022 mint
    pub mint: Pubkey,
    /// Vault ATA holding staked tokens
    pub vault_ata: Pubkey,
    /// Total amount currently staked
    pub total_staked: u64,
    /// Current epoch number
    pub epoch: u64,
    /// Slot when current epoch started
    pub epoch_start_slot: u64,
    /// Number of slots per epoch
    pub epoch_length_slots: u64,
    /// PDA bump
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct StakeRecord {
    /// Owner of this stake record
    pub owner: Pubkey,
    /// Pool this record belongs to
    pub pool: Pubkey,
    /// Amount staked
    pub amount: u64,
    /// Epoch when stake was last modified
    pub last_stake_epoch: u64,
    /// Slot when stake was last modified
    pub last_update_slot: u64,
    /// PDA bump
    pub bump: u8,
}

// ============================================================================
// INSTRUCTION CONTEXTS
// ============================================================================

#[derive(Accounts)]
pub struct InitializeGrill<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    /// The Token-2022 mint
    #[account(
        mint::token_program = token_program,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Pool PDA
    #[account(
        init,
        payer = admin,
        space = 8 + Pool::INIT_SPACE,
        seeds = [b"pool", mint.key().as_ref()],
        bump,
    )]
    pub pool: Account<'info, Pool>,

    /// Vault ATA owned by pool PDA
    #[account(
        init,
        payer = admin,
        associated_token::mint = mint,
        associated_token::authority = pool,
        associated_token::token_program = token_program,
    )]
    pub vault_ata: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositSteak<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"pool", pool.mint.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, Pool>,

    /// The Token-2022 mint
    #[account(
        address = pool.mint,
        mint::token_program = token_program,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    /// User's ATA
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = user,
        associated_token::token_program = token_program,
    )]
    pub user_ata: InterfaceAccount<'info, TokenAccount>,

    /// Pool's vault ATA
    #[account(
        mut,
        address = pool.vault_ata,
    )]
    pub vault_ata: InterfaceAccount<'info, TokenAccount>,

    /// User's stake record (created if needed)
    #[account(
        init_if_needed,
        payer = user,
        space = 8 + StakeRecord::INIT_SPACE,
        seeds = [b"stake", pool.key().as_ref(), user.key().as_ref()],
        bump,
    )]
    pub stake_record: Account<'info, StakeRecord>,

    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawSteak<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"pool", pool.mint.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, Pool>,

    /// The Token-2022 mint
    #[account(
        address = pool.mint,
        mint::token_program = token_program,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    /// User's ATA
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = user,
        associated_token::token_program = token_program,
    )]
    pub user_ata: InterfaceAccount<'info, TokenAccount>,

    /// Pool's vault ATA
    #[account(
        mut,
        address = pool.vault_ata,
    )]
    pub vault_ata: InterfaceAccount<'info, TokenAccount>,

    /// User's stake record
    #[account(
        mut,
        seeds = [b"stake", pool.key().as_ref(), user.key().as_ref()],
        bump = stake_record.bump,
        constraint = stake_record.owner == user.key() @ SteakError::Unauthorized,
    )]
    pub stake_record: Account<'info, StakeRecord>,

    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct RollEpoch<'info> {
    #[account(
        mut,
        seeds = [b"pool", pool.mint.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, Pool>,
}

#[derive(Accounts)]
pub struct UpdateEpochLength<'info> {
    #[account(
        constraint = admin.key() == pool.admin @ SteakError::Unauthorized,
    )]
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [b"pool", pool.mint.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, Pool>,
}

#[derive(Accounts)]
pub struct CloseStakeRecord<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        seeds = [b"pool", pool.mint.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, Pool>,

    #[account(
        mut,
        close = user,
        seeds = [b"stake", pool.key().as_ref(), user.key().as_ref()],
        bump = stake_record.bump,
        constraint = stake_record.owner == user.key() @ SteakError::Unauthorized,
    )]
    pub stake_record: Account<'info, StakeRecord>,
}

#[derive(Accounts)]
pub struct CloseGrill<'info> {
    #[account(
        mut,
        constraint = admin.key() == pool.admin @ SteakError::Unauthorized,
    )]
    pub admin: Signer<'info>,

    #[account(
        mut,
        close = admin,
        seeds = [b"pool", pool.mint.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Account<'info, Pool>,

    #[account(
        address = pool.vault_ata,
    )]
    pub vault_ata: InterfaceAccount<'info, TokenAccount>,
}


// ============================================================================
// EVENTS
// ============================================================================

#[event]
pub struct PoolInitializedEvent {
    pub pool: Pubkey,
    pub admin: Pubkey,
    pub mint: Pubkey,
    pub epoch_length_slots: u64,
    pub slot: u64,
}

#[event]
pub struct StakeEvent {
    pub pool: Pubkey,
    pub user: Pubkey,
    pub amount: u64,
    pub new_user_amount: u64,
    pub new_total: u64,
    pub epoch: u64,
    pub slot: u64,
}

#[event]
pub struct UnstakeEvent {
    pub pool: Pubkey,
    pub user: Pubkey,
    pub amount: u64,
    pub new_user_amount: u64,
    pub new_total: u64,
    pub epoch: u64,
    pub slot: u64,
}

#[event]
pub struct EpochRolledEvent {
    pub pool: Pubkey,
    pub new_epoch: u64,
    pub snapshot_slot: u64,
}

#[event]
pub struct EpochLengthUpdatedEvent {
    pub pool: Pubkey,
    pub old_length: u64,
    pub new_length: u64,
    pub slot: u64,
}


// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum SteakError {
    #[msg("Token program must be Token-2022")]
    InvalidTokenProgram,
    #[msg("Mint has unsupported extensions (TransferFee or TransferHook)")]
    UnsupportedMintExtension,
    #[msg("Invalid mint account")]
    InvalidMint,
    #[msg("Insufficient stake balance")]
    InsufficientStake,
    #[msg("Epoch not ready to roll yet")]
    EpochNotReady,
    #[msg("Math overflow")]
    MathOverflow,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Stake record has non-zero balance")]
    StakeRecordNotEmpty,
    #[msg("Pool has non-zero total staked")]
    PoolNotEmpty,
    #[msg("Vault has non-zero balance")]
    VaultNotEmpty,
    #[msg("Amount must be greater than zero")]
    InvalidAmount,
    #[msg("Stake amount too small (minimum 1 token)")]
    StakeTooSmall,
}
