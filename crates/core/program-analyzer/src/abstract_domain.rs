use syn::Stmt;
use crate::octagon_domain::OctagonState;

/// Strategy: "Shadow Integration" (Zero-Risk Approach)
/// STEP 1 — Introduce AbstractState (NO behavior change)
///
/// A generic abstract state that can hold multiple domains.
/// Currently only holds the Octagon domain.
#[derive(Clone, Debug, PartialEq)]
pub struct AbstractState {
    pub octagon: OctagonState,
    // Future domains (Intervals, Separation Logic, etc.) will be added here
}

/// Analysis context shared across the engine for guided operations.
pub struct AnalysisContext {
    pub thresholds: Vec<i128>,
}

impl AnalysisContext {
    pub fn new(thresholds: Vec<i128>) -> Self {
        Self { thresholds }
    }
}

impl Default for AbstractState {
    fn default() -> Self {
        Self {
            octagon: OctagonState::new(&[]),
        }
    }
}

impl AbstractState {
    pub fn join(&self, other: &Self) -> Self {
        Self {
            octagon: self.octagon.join(&other.octagon),
        }
    }

    pub fn widen(&self, other: &Self, context: &AnalysisContext) -> Self {
        println!("[Widening] Applying guided widening with {} thresholds", context.thresholds.len());
        Self {
            octagon: self.octagon.widen(&other.octagon, context),
        }
    }
}

/// STEP 2 — Wrap Octagon into a "Domain Interface"
///
/// A common interface for all abstract domains.
pub trait AbstractDomain {
    fn join(&self, other: &Self) -> Self;
    fn widen(&self, other: &Self, context: &AnalysisContext) -> Self;
    fn transfer(&self, stmt: &Stmt) -> Self;
}
