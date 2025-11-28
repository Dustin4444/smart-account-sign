// SPDX-License-Identifier: MIT
// Copyright (c) 2025

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;
use std::io::{self, Write};
use stellar_rpc_client::Client;
use stellar_xdr::curr::{
    ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo,
    MuxedAccount, Operation, OperationBody, Preconditions, PublicKey, ReadXdr, ScAddress, ScBytes,
    ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SequenceNumber, StringM, Transaction,
    TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM,
};

// Field name constants for type-safe parsing
const FIELD_CONTEXT_TYPE: &str = "context_type";
const FIELD_ID: &str = "id";
const FIELD_NAME: &str = "name";
const FIELD_POLICIES: &str = "policies";
const FIELD_SIGNERS: &str = "signers";
const FIELD_VALID_UNTIL: &str = "valid_until";

#[derive(Serialize, Clone, Debug)]
pub struct ContextRule {
    pub context_type: Option<String>,
    pub id: Option<u32>,
    pub name: Option<String>,
    pub policies: Vec<ContractId>,
    pub signers: Vec<Signer>,
    pub valid_until: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Signer {
    pub signer_type: StringM<32>,
    pub address: ScAddress,
    pub public_key: Option<ScBytes>,
    pub signer_vec: VecM<ScVal>,
}

/// Fetches all context rules from a smart account and displays them in a table
pub async fn get_context_rules_table(
    client: &Client,
    account_addr: &str,
) -> Result<Vec<ContextRule>> {
    let contract_addr =
        stellar_strkey::Contract::from_string(account_addr).context("Invalid smart account ID")?;
    let contract_address = ScAddress::Contract(ContractId(Hash(contract_addr.0)));

    let mut rules = Vec::new();
    let mut rule_id = 0u32;

    eprintln!(
        "{}",
        "Fetching authorization rules from smart account...".bright_cyan()
    );
    eprintln!(
        "{}\n",
        "(This determines who needs to sign the transaction)".bright_black()
    );

    loop {
        // Build invoke args for get_context_rule
        let function_name = ScSymbol("get_context_rule".try_into()?);
        let args: VecM<ScVal> = vec![ScVal::U32(rule_id)].try_into()?;

        let invoke_args = InvokeContractArgs {
            contract_address: contract_address.clone(),
            function_name,
            args,
        };

        // Build a minimal transaction envelope for simulation
        let host_function = HostFunction::InvokeContract(invoke_args);

        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function,
                auth: VecM::default(),
            }),
        };

        // Use a dummy source account for simulation
        let source = MuxedAccount::Ed25519(Uint256([0; 32]));

        let tx = Transaction {
            source_account: source,
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into()?,
            ext: TransactionExt::V0,
        };

        let tx_envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        // Simulate the transaction
        match client
            .simulate_transaction_envelope(&tx_envelope, None)
            .await
        {
            Ok(response) => {
                let results = response.results;
                if let Some(result_raw) = results.first() {
                    // Parse the XDR result
                    if let Ok(ScVal::Map(Some(scmap))) =
                        ScVal::from_xdr_base64(&result_raw.xdr, Limits::none())
                    {
                        let rule = extract_values(&scmap);
                        rules.push(rule);
                        rule_id += 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            Err(_) => {
                // No more rules found or error occurred
                break;
            }
        }
    }

    if rules.is_empty() {
        anyhow::bail!("No context rules available for this smart account");
    } else {
        display_rules_table(&rules);
    }

    Ok(rules)
}

fn display_rules_table(rules: &[ContextRule]) {
    eprintln!("\n{}", "Available Context Rules:".bright_white().bold());
    eprintln!(
        "{}\n",
        "Each rule defines a different authorization context.".bright_black()
    );

    for rule in rules {
        let id_str = rule
            .id
            .map(|i| i.to_string())
            .unwrap_or_else(|| "?".to_string());
        let name_str = rule.name.clone().unwrap_or_else(|| "Unnamed".to_string());
        let context_type_str = rule
            .context_type
            .clone()
            .unwrap_or_else(|| "N/A".to_string());

        // Box header
        let header = format!("Rule #{}: {}", id_str, name_str);
        let box_width = 100;
        eprintln!(
            "{}",
            format!("+-{:-<width$}-+", "", width = box_width).cyan()
        );
        eprintln!(
            "{}",
            format!("| {:<width$} |", header, width = box_width).cyan()
        );
        eprintln!(
            "{}",
            format!("+-{:-<width$}-+", "", width = box_width).cyan()
        );

        // Context type
        eprintln!(
            "{}  {}",
            "Context:".bright_white(),
            context_type_str.yellow()
        );

        // Signers
        if rule.signers.is_empty() {
            eprintln!("{}  {}", "Signers:".bright_white(), "None".bright_black());
        } else {
            let signer_count = rule.signers.len();
            let external_count = rule
                .signers
                .iter()
                .filter(|s| s.signer_type.to_string() == "External")
                .count();
            let delegated_count = signer_count - external_count;

            let summary = match (external_count, delegated_count) {
                (e, 0) => format!("{} External", e),
                (0, d) => format!("{} Delegated", d),
                (e, d) => format!("{} External, {} Delegated", e, d),
            };
            eprintln!("{}  {}", "Signers:".bright_white(), summary.green());

            for signer in rule.signers.iter() {
                let signer_type = signer.signer_type.to_string();

                let addr_str = match &signer.address {
                    ScAddress::Contract(contract_id) => {
                        stellar_strkey::Contract(contract_id.0.clone().into()).to_string()
                    }
                    ScAddress::Account(account_id) => match &account_id.0 {
                        PublicKey::PublicKeyTypeEd25519(uint256) => {
                            stellar_strkey::ed25519::PublicKey(uint256.0).to_string()
                        }
                    },
                    _ => "Unsupported".to_string(),
                };
                if signer_type == "External" {
                    let pubkey_str = signer
                        .public_key
                        .as_ref()
                        .map(|pk| hex::encode(&pk.0))
                        .unwrap_or_else(|| "N/A".to_string());
                    eprintln!(
                        "    {} {} {}",
                        "External:".bright_black(),
                        format!("({})", addr_str).bright_black(),
                        pubkey_str,
                    );
                } else {
                    eprintln!("    {} {}", "Delegated:".bright_black(), addr_str);
                }
            }
        }

        // Policies
        if rule.policies.is_empty() {
            eprintln!("{}  {}", "Policies:".bright_white(), "None".bright_black());
        } else {
            let policies_str = rule
                .policies
                .iter()
                .map(|policy| stellar_strkey::Contract(policy.0.clone().into()).to_string())
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!("{}  {}", "Policies:".bright_white(), policies_str);
        }

        // Valid until
        let valid_until_str = rule
            .valid_until
            .clone()
            .unwrap_or_else(|| "Never".to_string());
        eprintln!(
            "{}  {}",
            "Expires:".bright_white(),
            valid_until_str.bright_black()
        );

        eprintln!(
            "{}",
            format!("+-{:-<width$}-+", "", width = box_width).cyan()
        );
        eprintln!();
    }

    eprintln!(
        "{}",
        "Signers listed must provide signatures for the transaction.".bright_black()
    );
}

/// Prompt user to select a context rule
pub fn prompt_rule_selection(rules: &[ContextRule]) -> Result<ContextRule> {
    if rules.is_empty() {
        anyhow::bail!("No context rules available");
    }

    eprintln!(
        "\n{}",
        "💡 TIP: Choose the rule that matches your authorization context.".bright_yellow()
    );
    eprintln!(
        "{}\n",
        "Each rule specifies which signers are required for this transaction.".bright_black()
    );
    eprint!("{} ", "Enter the rule ID to use:".bright_white().bold());
    io::stderr().flush()?;
    let mut rule_id_input = String::new();
    io::stdin().read_line(&mut rule_id_input)?;
    let selected_rule_id: u32 = rule_id_input
        .trim()
        .parse()
        .context("Invalid rule ID. Please enter a number from the table above.")?;

    rules
        .iter()
        .find(|r| r.id == Some(selected_rule_id))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Rule with ID {} not found", selected_rule_id))
}

fn extract_values(scmap: &ScMap) -> ContextRule {
    let mut context_type = None;
    let mut id = None;
    let mut name = None;
    let mut policies = vec![];
    let mut signers = vec![];
    let mut valid_until = None;

    for ScMapEntry { key, val } in scmap.iter() {
        let ScVal::Symbol(ScSymbol(sym)) = key else {
            continue;
        };

        match sym.to_string().as_str() {
            FIELD_CONTEXT_TYPE => {
                context_type = match val {
                    ScVal::Vec(Some(ScVec(values))) => {
                        let type_name = values.as_slice().first().and_then(|v| match v {
                            ScVal::Symbol(ScSymbol(s)) => Some(s.to_string()),
                            _ => None,
                        });

                        // Check for optional second parameter (ContractId)
                        let contract_param = values.as_slice().get(1).and_then(|v| match v {
                            ScVal::Address(ScAddress::Contract(contract_id)) => Some(
                                stellar_strkey::Contract(contract_id.0.clone().into()).to_string(),
                            ),
                            _ => None,
                        });

                        match (type_name, contract_param) {
                            (Some(name), Some(contract)) => {
                                Some(format!("{} ({})", name, contract))
                            }
                            (Some(name), None) => Some(name),
                            _ => None,
                        }
                    }
                    _ => None,
                };
            }
            FIELD_ID => {
                id = match val {
                    ScVal::U32(v) => Some(*v),
                    _ => None,
                };
            }
            FIELD_NAME => {
                name = match val {
                    ScVal::String(ScString(v)) => Some(String::from_utf8_lossy(v).to_string()),
                    _ => None,
                };
            }
            FIELD_POLICIES => {
                if let ScVal::Vec(Some(ScVec(vec))) = val {
                    policies = vec
                        .as_slice()
                        .iter()
                        .filter_map(|policy| match policy {
                            ScVal::Address(ScAddress::Contract(contract)) => Some(contract.clone()),
                            _ => None,
                        })
                        .collect();
                }
            }
            FIELD_SIGNERS => {
                if let ScVal::Vec(Some(ScVec(vec_outer))) = val {
                    signers = vec_outer
                        .as_slice()
                        .iter()
                        .filter_map(|signer_vec| {
                            let ScVal::Vec(Some(ScVec(inner))) = signer_vec else {
                                return None;
                            };

                            let ScVal::Symbol(ScSymbol(signer_type)) = &inner.as_slice()[0] else {
                                return None;
                            };

                            let address = match inner.as_slice().get(1)? {
                                ScVal::Address(addr) => addr.clone(),
                                _ => return None,
                            };

                            let public_key = inner.as_slice().get(2).and_then(|val| match val {
                                ScVal::Bytes(bytes) => Some(bytes.clone()),
                                _ => None,
                            });

                            Some(Signer {
                                signer_type: signer_type.clone(),
                                address,
                                public_key,
                                signer_vec: inner.clone(),
                            })
                        })
                        .collect();
                }
            }
            FIELD_VALID_UNTIL => {
                valid_until = match val {
                    ScVal::Void => None,
                    _ => Some(format!("{:?}", val)),
                };
            }
            _ => {}
        }
    }

    ContextRule {
        context_type,
        id,
        name,
        policies,
        signers,
        valid_until,
    }
}
