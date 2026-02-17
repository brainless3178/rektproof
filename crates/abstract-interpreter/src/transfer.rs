//! Transfer Functions for Abstract Interpretation
//!
//! Implements the abstract semantics (transfer functions) for Solana
//! program operations. These functions compute the output abstract
//! value from input abstract values, forming the core of the
//! abstract interpretation framework.
//!
//! Mathematical foundation:
//!   Given concrete semantics f: V → V and abstraction α: V → V#,
//!   the transfer function f#: V# → V# must satisfy:
//!     α(f(γ(v#))) ⊑ f#(v#)   (soundness via Galois connection)

use crate::domains::{Congruence, Sign};
use crate::Interval;
use std::collections::HashMap;
use syn::{BinOp, Expr, Lit};

/// Transfer functions for interval-domain abstract interpretation.
///
/// Each function maps abstract input(s) to an abstract output, ensuring
/// soundness: the concrete result is always contained in the abstract result.
pub struct TransferFunctions;

impl TransferFunctions {
    /// Evaluate an expression in the interval domain.
    ///
    /// Given a mapping from variable names to intervals, this computes
    /// the tightest interval that is guaranteed to contain all possible
    /// concrete values of the expression.
    pub fn eval_expr(expr: &Expr, state: &HashMap<String, Interval>) -> Interval {
        match expr {
            Expr::Lit(lit_expr) => {
                if let Lit::Int(lit_int) = &lit_expr.lit {
                    lit_int
                        .base10_parse::<i128>()
                        .map(Interval::singleton)
                        .unwrap_or(Interval::u128_range())
                } else {
                    Interval::u128_range()
                }
            }
            Expr::Path(path) => {
                if let Some(ident) = path.path.get_ident() {
                    state
                        .get(&ident.to_string())
                        .copied()
                        .unwrap_or(Interval::u64_range())
                } else {
                    Interval::u64_range()
                }
            }
            Expr::Binary(binary) => {
                let left = Self::eval_expr(&binary.left, state);
                let right = Self::eval_expr(&binary.right, state);
                Self::eval_binop(&binary.op, left, right)
            }
            Expr::Paren(paren) => Self::eval_expr(&paren.expr, state),
            Expr::Cast(cast) => Self::eval_expr(&cast.expr, state),
            Expr::MethodCall(mc) => {
                let receiver = Self::eval_expr(&mc.receiver, state);
                if !mc.args.is_empty() {
                    let arg = Self::eval_expr(&mc.args[0], state);
                    Self::eval_checked_method(&mc.method.to_string(), receiver, arg)
                } else {
                    receiver
                }
            }
            _ => Interval::u64_range(),
        }
    }

    /// Abstract transfer function for binary operations.
    ///
    /// For op ∈ {+, -, *, /}, computes [a_lo op b_lo, a_hi op b_hi]
    /// (taking all four combinations for * and / to handle sign).
    pub fn eval_binop(op: &BinOp, left: Interval, right: Interval) -> Interval {
        match op {
            BinOp::Add(_) => left + right,
            BinOp::Sub(_) => left - right,
            BinOp::Mul(_) => left * right,
            BinOp::Div(_) => left / right,
            BinOp::Rem(_) => Self::eval_rem(left, right),
            BinOp::BitAnd(_) => Self::eval_bitand(left, right),
            BinOp::BitOr(_) => Self::eval_bitor(left, right),
            BinOp::Shl(_) => Self::eval_shl(left, right),
            BinOp::Shr(_) => Self::eval_shr(left, right),
            _ => Interval::u64_range(),
        }
    }

    /// Transfer function for checked arithmetic (returns same interval
    /// since checked_add returns `Option` — we model the success path).
    fn eval_checked_method(method: &str, receiver: Interval, arg: Interval) -> Interval {
        match method {
            "checked_add" => receiver + arg,
            "checked_sub" => receiver - arg,
            "checked_mul" => receiver * arg,
            "checked_div" => {
                if arg.contains(0) {
                    // Division by zero possible — widen to full range
                    Interval::u64_range()
                } else {
                    receiver / arg
                }
            }
            "saturating_add" => {
                let result = receiver + arg;
                Interval::new(result.min, result.max.min(u64::MAX as i128))
            }
            "saturating_sub" => {
                let result = receiver - arg;
                Interval::new(result.min.max(0), result.max)
            }
            "saturating_mul" => {
                let result = receiver * arg;
                Interval::new(result.min, result.max.min(u64::MAX as i128))
            }
            "min" => Interval::new(receiver.min.min(arg.min), receiver.max.min(arg.max)),
            "max" => Interval::new(receiver.min.max(arg.min), receiver.max.max(arg.max)),
            _ => Interval::u64_range(),
        }
    }

    /// Transfer function for remainder (modulo).
    ///
    /// If b ∈ [b_lo, b_hi] and b > 0, then a % b ∈ [0, b_hi - 1].
    fn eval_rem(left: Interval, right: Interval) -> Interval {
        if left.is_bottom() || right.is_bottom() {
            return Interval::bottom();
        }
        if right.max <= 0 {
            return Interval::u64_range(); // Modulo by non-positive — undefined
        }
        // Result is in [0, |right.max| - 1] for non-negative left
        if left.min >= 0 {
            Interval::new(0, right.max.abs() - 1)
        } else {
            Interval::new(-(right.max.abs() - 1), right.max.abs() - 1)
        }
    }

    /// Transfer for bitwise AND: both bits must be 1.
    ///
    /// Upper bound: min(a.max, b.max) since AND can only clear bits.
    fn eval_bitand(left: Interval, right: Interval) -> Interval {
        if left.is_bottom() || right.is_bottom() {
            return Interval::bottom();
        }
        if left.min >= 0 && right.min >= 0 {
            Interval::new(0, left.max.min(right.max))
        } else {
            Interval::u64_range()
        }
    }

    /// Transfer for bitwise OR: either bit being 1 suffices.
    fn eval_bitor(left: Interval, right: Interval) -> Interval {
        if left.is_bottom() || right.is_bottom() {
            return Interval::bottom();
        }
        if left.min >= 0 && right.min >= 0 {
            Interval::new(left.min.max(right.min), left.max | right.max)
        } else {
            Interval::u64_range()
        }
    }

    /// Transfer for left shift: a << b.
    ///
    /// If b is known, multiplies by 2^b. If b is a range, widen.
    fn eval_shl(left: Interval, right: Interval) -> Interval {
        if left.is_bottom() || right.is_bottom() {
            return Interval::bottom();
        }
        if right.min == right.max && right.min >= 0 && right.min < 64 {
            let shift = right.min as u32;
            Interval::new(
                left.min.saturating_mul(1i128 << shift),
                left.max.saturating_mul(1i128 << shift),
            )
        } else {
            Interval::u64_range()
        }
    }

    /// Transfer for right shift: a >> b.
    fn eval_shr(left: Interval, right: Interval) -> Interval {
        if left.is_bottom() || right.is_bottom() {
            return Interval::bottom();
        }
        if right.min == right.max && right.min >= 0 && right.min < 64 {
            let shift = right.min as u32;
            Interval::new(left.min >> shift, left.max >> shift)
        } else if left.min >= 0 {
            Interval::new(0, left.max)
        } else {
            Interval::u64_range()
        }
    }

    // ─── Narrowing ───────────────────────────────────────────────────────
    //
    // After widening reaches a post-fixpoint, narrowing refines the
    // result by iterating the transfer function "downward" in the lattice.
    //
    // Narrowing operator ∆:
    //   a ∆ b = [if b.min > a.min then b.min else a.min,
    //            if b.max < a.max then b.max else a.max]

    /// Narrowing operator for intervals.
    ///
    /// Given a post-fixpoint `old` obtained by widening, and a new
    /// application of the transfer function `new`, tighten the bounds
    /// only where the new computation gives a strictly tighter bound.
    pub fn narrow(old: Interval, new: Interval) -> Interval {
        if old.is_bottom() {
            return new;
        }
        if new.is_bottom() {
            return old;
        }
        let narrowed_min = if new.min > old.min { new.min } else { old.min };
        let narrowed_max = if new.max < old.max { new.max } else { old.max };
        Interval::new(narrowed_min, narrowed_max)
    }

    // ─── Reduced Product ────────────────────────────────────────────────
    //
    // Combines Interval × Sign domains. After computing in each domain
    // independently, use the reduction to tighten:
    //   If sign(v) = Positive, then interval.min = max(interval.min, 1)
    //   If sign(v) = NonNegative, then interval.min = max(interval.min, 0)

    /// Reduce an interval using sign information.
    pub fn reduce_with_sign(interval: Interval, sign: Sign) -> Interval {
        if interval.is_bottom() {
            return interval;
        }
        match sign {
            Sign::Positive => Interval::new(interval.min.max(1), interval.max),
            Sign::Negative => Interval::new(interval.min, interval.max.min(-1)),
            Sign::Zero => Interval::singleton(0),
            Sign::NonNegative => Interval::new(interval.min.max(0), interval.max),
            Sign::NonPositive => Interval::new(interval.min, interval.max.min(0)),
            _ => interval,
        }
    }

    /// Reduce an interval using congruence information.
    ///
    /// If we know x ≡ r (mod m) and x ∈ [lo, hi], we can tighten
    /// lo to the smallest value ≥ lo that is ≡ r (mod m).
    pub fn reduce_with_congruence(interval: Interval, cong: Congruence) -> Interval {
        if interval.is_bottom() || cong.modulus == 0 {
            return interval;
        }

        let m = cong.modulus as i128;
        let r = cong.remainder as i128;

        // Tighten min: smallest value >= interval.min that is ≡ r (mod m)
        let rem = ((interval.min % m) + m) % m;
        let new_min = if rem == r {
            interval.min
        } else if r > rem {
            interval.min + (r - rem)
        } else {
            interval.min + (m - rem + r)
        };

        // Tighten max: largest value <= interval.max that is ≡ r (mod m)
        let rem_max = ((interval.max % m) + m) % m;
        let new_max = if rem_max == r {
            interval.max
        } else if r < rem_max {
            interval.max - (rem_max - r)
        } else {
            interval.max - (m - r + rem_max)
        };

        if new_min > new_max {
            Interval::bottom()
        } else {
            Interval::new(new_min, new_max)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_binop_add() {
        let a = Interval::new(10, 20);
        let b = Interval::new(5, 15);
        let result = TransferFunctions::eval_binop(&BinOp::Add(Default::default()), a, b);
        assert_eq!(result.min, 15);
        assert_eq!(result.max, 35);
    }

    #[test]
    fn test_eval_binop_sub() {
        let a = Interval::new(10, 20);
        let b = Interval::new(5, 15);
        let result = TransferFunctions::eval_binop(&BinOp::Sub(Default::default()), a, b);
        // 10-15 = -5, 20-5 = 15
        assert_eq!(result.min, -5);
        assert_eq!(result.max, 15);
    }

    #[test]
    fn test_eval_binop_mul() {
        let a = Interval::new(2, 4);
        let b = Interval::new(3, 5);
        let result = TransferFunctions::eval_binop(&BinOp::Mul(Default::default()), a, b);
        assert_eq!(result.min, 6);
        assert_eq!(result.max, 20);
    }

    #[test]
    fn test_eval_rem() {
        let a = Interval::new(0, 100);
        let b = Interval::new(10, 10);
        let result = TransferFunctions::eval_rem(a, b);
        assert_eq!(result.min, 0);
        assert_eq!(result.max, 9);
    }

    #[test]
    fn test_eval_bitand() {
        let a = Interval::new(0, 255);
        let b = Interval::new(0, 15);
        let result = TransferFunctions::eval_bitand(a, b);
        assert_eq!(result.min, 0);
        assert_eq!(result.max, 15); // AND with mask ≤ 15
    }

    #[test]
    fn test_eval_shl() {
        let a = Interval::new(1, 4);
        let b = Interval::singleton(3);
        let result = TransferFunctions::eval_shl(a, b);
        assert_eq!(result.min, 8);  // 1 << 3
        assert_eq!(result.max, 32); // 4 << 3
    }

    #[test]
    fn test_eval_shr() {
        let a = Interval::new(16, 64);
        let b = Interval::singleton(2);
        let result = TransferFunctions::eval_shr(a, b);
        assert_eq!(result.min, 4);  // 16 >> 2
        assert_eq!(result.max, 16); // 64 >> 2
    }

    #[test]
    fn test_narrowing() {
        // After widening we got [0, MAX/2], but recomputation gives [5, 100]
        let widened = Interval::new(0, i128::MAX / 2);
        let recomputed = Interval::new(5, 100);
        let narrowed = TransferFunctions::narrow(widened, recomputed);
        // Narrowing tightens both bounds
        assert_eq!(narrowed.min, 5);
        assert_eq!(narrowed.max, 100);
    }

    #[test]
    fn test_narrowing_partial() {
        // Only upper bound tightens
        let widened = Interval::new(0, 1000);
        let recomputed = Interval::new(-10, 500);
        let narrowed = TransferFunctions::narrow(widened, recomputed);
        assert_eq!(narrowed.min, 0);   // -10 is NOT tighter than 0
        assert_eq!(narrowed.max, 500); // 500 IS tighter than 1000
    }

    #[test]
    fn test_reduce_with_sign() {
        let interval = Interval::new(-10, 100);
        let reduced = TransferFunctions::reduce_with_sign(interval, Sign::Positive);
        assert_eq!(reduced.min, 1);
        assert_eq!(reduced.max, 100);
    }

    #[test]
    fn test_reduce_with_sign_nonneg() {
        let interval = Interval::new(-10, 100);
        let reduced = TransferFunctions::reduce_with_sign(interval, Sign::NonNegative);
        assert_eq!(reduced.min, 0);
        assert_eq!(reduced.max, 100);
    }

    #[test]
    fn test_reduce_with_congruence() {
        // x ∈ [0, 100] and x ≡ 3 (mod 10)
        let interval = Interval::new(0, 100);
        let cong = Congruence::new(10, 3);
        let reduced = TransferFunctions::reduce_with_congruence(interval, cong);
        assert_eq!(reduced.min, 3);   // smallest ≥ 0 that is ≡ 3 mod 10
        assert_eq!(reduced.max, 93);  // largest ≤ 100 that is ≡ 3 mod 10
    }

    #[test]
    fn test_reduce_with_congruence_empty() {
        // x ∈ [10, 11] and x ≡ 0 (mod 100) → empty
        let interval = Interval::new(10, 11);
        let cong = Congruence::new(100, 0);
        let reduced = TransferFunctions::reduce_with_congruence(interval, cong);
        assert!(reduced.is_bottom());
    }

    #[test]
    fn test_saturating_add_transfer() {
        let a = Interval::new(u64::MAX as i128 - 10, u64::MAX as i128);
        let b = Interval::new(5, 20);
        let result = TransferFunctions::eval_checked_method("saturating_add", a, b);
        // Should be clamped at u64::MAX
        assert_eq!(result.max, u64::MAX as i128);
    }

    #[test]
    fn test_method_min_max() {
        let a = Interval::new(5, 20);
        let b = Interval::new(10, 30);

        let min_result = TransferFunctions::eval_checked_method("min", a, b);
        assert_eq!(min_result.min, 5);
        assert_eq!(min_result.max, 20);

        let max_result = TransferFunctions::eval_checked_method("max", a, b);
        assert_eq!(max_result.min, 10);
        assert_eq!(max_result.max, 30);
    }
}
