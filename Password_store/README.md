# Security Assessment: PasswordStore Protocol

> Independent smart contract security review for the **PasswordStore** protocol. The primary focus of this assessment was to validate the storage architecture and access boundaries against its intended business logic, ensuring the protocol securely handles state modifications and sensitive data retention.

---

## Executive Summary

| Field | Details |
| :--- | :--- |
| **Auditor** | Denzel Abelle |
| **Date** | May 26, 2026 |
| **Scope** | `PasswordStore` core implementation |
| **Key Findings** | 2 High Severity, 2 Informational |

The protocol's objective is straightforward: provide an isolated on-chain repository where only an authorized owner can store and retrieve a private password. However, the current implementation contains structural flaws that completely break both data confidentiality and state integrity.

---

## Summary Matrix

| Reference | Vulnerability | Severity | Status |
| :--- | :--- | :---: | :---: |
| **[H-1]** | Zero Confidentiality: Plaintext Storage on Public Ledger | 🔴 High | Open |
| **[H-2]** | Missing Access Control on Critical State Mutator | 🔴 High | Open |
| **[I-1]** | Dead Parameter Reference in NatSpec Documentation | 🔵 Informational | Open |
| **[I-2]** | Silent State Changes via Unlogged Actor Address | 🔵 Informational | Open |

---

## Detailed Technical Findings

### 1. High Severity

---

#### 🚨 [H-1] Zero Confidentiality: Plaintext Storage on Public Ledger

- **Context:** The implementation relies on the `private` visibility modifier for `PasswordStore::s_password`, assuming it isolates the secret from external eyes.

- **The Reality:** Visibility keywords in Solidity only restrict *smart contract compilation access*, not on-chain read access. Because the Ethereum state ledger is entirely public, any data committed to contract storage slots can be read directly off-chain.

- **Impact:** Complete failure of the contract's primary security guarantee. The stored password is fully public.

**Proof of Concept:**

Using the Foundry toolchain, an external observer can bypass the contract interface entirely and pull the raw hex from storage slot 1:

```bash
# Query the raw storage slot directly from the JSON-RPC endpoint
cast storage <CONTRACT_ADDRESS> 1 --rpc-url <RPC_URL>

# Decode the resulting bytes32 hex array back to a string
cast parse-bytes32-string <HEX_RESULT>
# Returns: "mySecretPassword"
```

- **Remediation:** Do not store plaintext secrets on-chain. If the contract only needs to verify identity or a credential, store a cryptographic hash instead (e.g., `keccak256`). If retrieval is mandatory, the data must be encrypted off-chain before submission and decrypted off-chain post-retrieval.

---

#### 🚨 [H-2] Missing Access Control on Critical State Mutator

- **Context:** The `PasswordStore::setPassword` function is exposed externally. While the documentation notes that *"This function allows only the owner to set a new password,"* the code lacks any logic enforcing this rule.

- **The Reality:** The function lacks standard modifiers or explicit validation checks (e.g., checking `msg.sender` against the designated owner).

- **Impact:** Complete loss of data integrity. Any arbitrary address can invoke this function and overwrite the contract's central state variable at will.

- **Remediation:** Introduce structural authorization guarding the state change. Implement an explicit identity check or a custom error pattern to revert unauthorized calls.

---

### 2. Informational Findings

---

#### ℹ️ [I-1] Dead Parameter Reference in NatSpec Documentation

- **Observation:** The inline NatSpec documentation for `getPassword` explicitly documents a `@param newPassword`. However, the actual function signature accepts zero arguments.

- **Impact:** Low; code clarity issue. It creates friction for external developers or automated indexing tools mapping the codebase.

- **Remediation:** Strip the inaccurate `@param` tag from the documentation block.

---

#### ℹ️ [I-2] Silent State Changes via Unlogged Actor Address

- **Observation:** The `SetNewPassword` event logs the occurrence of a change but carries no payloads or indexed parameters.

- **Impact:** Complicates post-deployment monitoring. Off-chain applications, subgraphs, and DevOps monitoring systems cannot extract who updated the state without reconstructing and parsing full transaction traces.

- **Remediation:** Add context to the event payload by logging and indexing the transaction caller.

---

## Tooling and Methodology

This assessment involved a thorough manual code review alongside the construction of deterministic exploit scripts and storage slot evaluations utilizing the **Foundry** environment.

---

## Disclaimer

> This report isolates specific architectural observations within the provided scope and represents a point-in-time evaluation. It does not constitute a definitive guarantee against undiscovered logical errors or future runtime vulnerabilities.
