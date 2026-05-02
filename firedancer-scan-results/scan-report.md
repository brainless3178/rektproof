# [shield] Proktor Security Audit Report

**Target:** `/home/elliot/Downloads/firedancer-0.812.30108/contrib`  
**Duration:** 39.1s  
**Score:** 65 / 100 (Grade: **C+**)  

---

## 📊 Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 1 |
| 🔵 Low | 0 |
| **Total** | **3** |

---

## 🔍 Detailed Findings

### 1. 🟠 SOL-089 - Account Resurrection via Close Without Zeroing

**Severity:** 🟠 HIGH | **Confidence:** 69% | **Category:** Account Lifecycle

**CWE:** [CWE-672](https://cwe.mitre.org/data/definitions/672.html)  
**Location:** `ledgers.rs` -> `bpf_loader_ledger()` (line 17)  

**Description:**  
Account is closed (lamports set to 0) without zeroing data or setting CLOSED_ACCOUNT_DISCRIMINATOR. Within the same slot, the account can be 'resurrected' by sending lamports back, exposing stale data.

**Vulnerable Code:**
```rust
#[doc = " CI Link: gs://firedancer-ci-resources/v18multi-bpf-loader.tar.gz"] pub fn bpf_loader_ledger (client : & RpcClient , arc_client : & Arc < RpcClient > , payer : & Keypair , program_data : & Vec<u8 > , account_data : & Vec<u8 >) { bpf_loader :: deploy_invoke_same_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: deploy_invoke_diff_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: upgrade_invoke_same_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: upgrade_invoke_diff_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: deploy_close_same_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: deploy_close_diff_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: close_invoke_same_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: close_invoke_diff_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: close_redeploy_same_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: close_redeploy_diff_slot (& client , & arc_client , & payer , & program_data , & account_data) ; }
```

**Attack Scenario:**  
TX1: Close account (lamports=0, data intact). TX2 (same slot): Send 1 lamport back. Account is revived with old data. Double-withdraw or state replay becomes possible.

**Recommended Fix:**
```rust
Zero data before close: `data.fill(0)` then set lamports to 0. Or use Anchor's `#[account(close = recipient)]` which handles this automatically.
```

---

### 2. 🟠 SOL-TAINT-02 - Tainted Data Reaching CPI Invocation

**Severity:** 🟠 HIGH | **Confidence:** 62% | **Category:** Information Flow

**CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html)  
**Location:** `instructions.rs` -> `invoke_program_instructions()` (line 198)  

**Description:**  
Taint analysis detected that variable `account_data` (taint level: AccountInput) flows from User-supplied key or data to a security-sensitive operation `CPI Invocation` in `invoke_program_instructions`. The data has taint level AccountInput but the sink requires at most SignerControlled. Fixed-point reached after 8 iterations.

**Vulnerable Code:**
```rust
let invoke_instruction = Instruction::new_with_bytes(
```

**Attack Scenario:**  
Tainted data flows to a cross-program invocation. The callee program may not validate the data, leading to cross-contract exploitation.

**Recommended Fix:**
```rust
Validate `account_data` before passing to `CPI Invocation`. Add bounds checking, signer verification, or account ownership validation.
```

---

### 3. 🟡 SOL-062 - Unbounded Input Length

**Severity:** 🟡 MEDIUM | **Confidence:** 59% | **Category:** Input Validation

**CWE:** [CWE-400](https://cwe.mitre.org/data/definitions/400.html)  
**Location:** `ledgers.rs` -> `bpf_loader_ledger()` (line 17)  

**Description:**  
Instruction accepts Vec<> input without length bounds. An attacker can pass an extremely large array to consume all compute units or cause excessive memory allocation.

**Vulnerable Code:**
```rust
#[doc = " CI Link: gs://firedancer-ci-resources/v18multi-bpf-loader.tar.gz"] pub fn bpf_loader_ledger (client : & RpcClient , arc_client : & Arc < RpcClient > , payer : & Keypair , program_data : & Vec<u8 > , account_data : & Vec<u8 >) { bpf_loader :: deploy_invoke_same_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: deploy_invoke_diff_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: upgrade_invoke_same_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: upgrade_invoke_diff_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: deploy_close_same_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: deploy_close_diff_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: close_invoke_same_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: close_invoke_diff_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: close_redeploy_same_slot (& client , & arc_client , & payer , & program_data , & account_data) ; bpf_loader :: close_redeploy_diff_slot (& client , & arc_client , & payer , & program_data , & account_data) ; }
```

**Attack Scenario:**  
Attacker passes a Vec with 10,000 elements. The instruction tries to iterate and runs out of compute units, DOS-ing the program.

**Recommended Fix:**
```rust
Add length validation: `require!(items.len() <= MAX_ITEMS)`. Define reasonable constants for maximum array sizes.
```

---

## 🛠️ Remediation Priority

| # | ID | Type | Severity | Location | Line |
|---|----|----|----------|----------|------|
| 1 | SOL-089 | Account Resurrection via Close Without Zeroing | 🟠 HIGH | `ledgers.rs` | 17 |
| 2 | SOL-TAINT-02 | Tainted Data Reaching CPI Invocation | 🟠 HIGH | `instructions.rs` | 198 |
| 3 | SOL-062 | Unbounded Input Length | 🟡 MEDIUM | `ledgers.rs` | 17 |

---

*Generated by [Proktor](https://proktor.security) - Enterprise-Grade Solana Security Platform*

