//! API Response Time Benchmarks
//!
//! Measures endpoint response latency to establish performance baselines.
//! Run with: `cargo bench --package shanon-api`
//!
//! Benchmarks are separated from tests to avoid conflating correctness
//! validation with performance validation.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use program_analyzer::{ProgramAnalyzer, VulnerabilityFinding};

const SAMPLE_PROGRAM: &str = r#"
use anchor_lang::prelude::*;

#[program]
pub mod sample {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let account = &mut ctx.accounts.my_account;
        account.data = 0;
        Ok(())
    }

    pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        let from = &mut ctx.accounts.from;
        let to = &mut ctx.accounts.to;
        from.balance = from.balance.checked_sub(amount).ok_or(ErrorCode::InsufficientFunds)?;
        to.balance = to.balance.checked_add(amount).ok_or(ErrorCode::Overflow)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = user, space = 8 + 8)]
    pub my_account: Account<'info, MyAccount>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}

#[account]
pub struct MyAccount {
    pub data: u64,
}

#[account]
pub struct TokenAccount {
    pub balance: u64,
    pub owner: Pubkey,
}
"#;

/// Benchmark: How long does it take to create an analyzer and parse a program?
fn bench_analyzer_creation(c: &mut Criterion) {
    c.bench_function("analyzer_create_and_parse", |b| {
        b.iter(|| {
            let _analyzer = ProgramAnalyzer::from_source(black_box(SAMPLE_PROGRAM));
        });
    });
}

/// Benchmark: Raw vulnerability scanning (without validation pipeline)
fn bench_raw_scan(c: &mut Criterion) {
    let analyzer = ProgramAnalyzer::from_source(SAMPLE_PROGRAM);
    c.bench_function("scan_raw_72_patterns", |b| {
        b.iter(|| {
            let findings: Vec<VulnerabilityFinding> = black_box(&analyzer)
                .scan_for_vulnerabilities_raw();
            black_box(findings);
        });
    });
}

/// Benchmark: Full validated scan (parse + scan + validation pipeline)
fn bench_validated_scan(c: &mut Criterion) {
    let analyzer = ProgramAnalyzer::from_source(SAMPLE_PROGRAM);
    c.bench_function("scan_validated_full_pipeline", |b| {
        b.iter(|| {
            let findings: Vec<VulnerabilityFinding> = black_box(&analyzer)
                .scan_for_vulnerabilities();
            black_box(findings);
        });
    });
}

/// Benchmark: Scaling with program size
fn bench_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_scaling");

    for multiplier in [1, 5, 10].iter() {
        let source = SAMPLE_PROGRAM.repeat(*multiplier);
        let analyzer = ProgramAnalyzer::from_source(&source);

        group.bench_with_input(
            BenchmarkId::new("raw_scan", format!("{}x", multiplier)),
            multiplier,
            |b, _| {
                b.iter(|| {
                    let findings = black_box(&analyzer).scan_for_vulnerabilities_raw();
                    black_box(findings);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_analyzer_creation,
    bench_raw_scan,
    bench_validated_scan,
    bench_scaling,
);
criterion_main!(benches);
