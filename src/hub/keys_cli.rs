//! `sentinel hub-key` — manage hub API keys.
//!
//! Keys are generated here, shown exactly once, and stored only as an
//! argon2 hash plus the public `key_id` lookup prefix. Three roles exist:
//! agent (identity-bound), app (identity-bound), dashboard (read-only).

use clap::Subcommand;
use tracing::info;

use crate::db::pool::create_pool;
use crate::db::repositories::api_key_repo::{ApiKeyRepository, InsertApiKey};
use crate::error::SentinelError;
use crate::hub::auth::{Permission, generate_key, hash_key};

#[derive(Debug, Clone, Subcommand)]
pub enum HubKeyAction {
    /// Create a new key; prints the raw key exactly once.
    Create {
        /// Bind an agent key to this agent id.
        #[arg(long)]
        agent: Option<String>,
        /// Hostname stored with an agent key (defaults to the agent id).
        #[arg(long)]
        hostname: Option<String>,
        /// Bind an app key to this app name.
        #[arg(long)]
        app: Option<String>,
        /// Create a read-only dashboard key with this display name.
        #[arg(long)]
        dashboard: Option<String>,
    },
    /// List keys (metadata only — secrets are never stored or shown).
    List,
    /// Revoke a key by its public `key_id`.
    Revoke {
        /// The 8-hex key id (the segment after `snt_`).
        key_id: String,
    },
}

/// Role selector: exactly one must be provided.
#[derive(Debug)]
struct Role {
    name: String,
    agent_id: Option<String>,
    hostname: Option<String>,
    app_name: Option<String>,
    permissions: Vec<String>,
}

impl Role {
    fn from_action(action: &HubKeyAction) -> Result<Option<Self>, SentinelError> {
        let HubKeyAction::Create {
            agent,
            hostname,
            app,
            dashboard,
        } = action
        else {
            return Ok(None);
        };

        let chosen = [agent.is_some(), app.is_some(), dashboard.is_some()]
            .iter()
            .filter(|chosen| **chosen)
            .count();
        if chosen != 1 {
            return Err(SentinelError::ConfigError(
                "hub-key create requires exactly one of --agent, --app, or --dashboard".into(),
            ));
        }

        if let Some(agent_id) = agent {
            return Ok(Some(Self {
                name: agent_id.clone(),
                agent_id: Some(agent_id.clone()),
                hostname: Some(hostname.clone().unwrap_or_else(|| agent_id.clone())),
                app_name: None,
                permissions: vec![
                    Permission::IngestMetrics.as_str().into(),
                    Permission::IngestLogs.as_str().into(),
                ],
            }));
        }
        if let Some(app_name) = app {
            return Ok(Some(Self {
                name: app_name.clone(),
                agent_id: None,
                hostname: None,
                app_name: Some(app_name.clone()),
                permissions: vec![Permission::IngestEvents.as_str().into()],
            }));
        }
        let dashboard_name = dashboard.as_ref().expect("chosen > 0 implies a role");
        Ok(Some(Self {
            name: dashboard_name.clone(),
            agent_id: None,
            hostname: None,
            app_name: None,
            permissions: vec![Permission::ReadDashboard.as_str().into()],
        }))
    }
}

/// Runs the `hub-key` subcommand. `database_url` comes from the caller
/// (which already resolved `DATABASE_URL`).
///
/// # Errors
/// Configuration, database, or key-management failures.
pub async fn run(action: HubKeyAction, database_url: &str) -> Result<(), SentinelError> {
    let pool = create_pool(database_url).await?;
    let repo = ApiKeyRepository::new(pool);

    match &action {
        HubKeyAction::Create { .. } => {
            let Some(role) = Role::from_action(&action)? else {
                return Err(SentinelError::Internal(
                    "create handled without role".into(),
                ));
            };
            let (raw_key, key_id) = generate_key();
            let hash = hash_key(&raw_key)?;
            let row = repo
                .create(&InsertApiKey {
                    name: role.name,
                    hash,
                    permissions: role.permissions,
                    key_id: key_id.clone(),
                    agent_id: role.agent_id,
                    hostname: role.hostname,
                    app_name: role.app_name,
                })
                .await?;

            println!("API key created for '{}'", row.name);
            println!("  key_id:   {key_id}");
            println!("  role:     {:?}", row.role());
            println!("  key:      {raw_key}");
            println!();
            println!("Store this key now — it is shown exactly once and never again.");
            Ok(())
        }
        HubKeyAction::List => {
            let keys = repo.list().await?;
            if keys.is_empty() {
                println!("No API keys.");
                return Ok(());
            }
            println!(
                "{:<12} {:<20} {:<10} {:<24} {:<10}",
                "KEY_ID", "NAME", "ROLE", "LAST_USED", "REVOKED"
            );
            for k in keys {
                let last_used = k.last_used_at.map_or_else(
                    || "never".into(),
                    |t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                );
                let revoked = if k.revoked_at.is_some() { "yes" } else { "no" };
                println!(
                    "{:<12} {:<20} {:<10} {:<24} {:<10}",
                    k.key_id,
                    truncate(&k.name, 20),
                    format!("{:?}", k.role()).to_uppercase(),
                    last_used,
                    revoked
                );
            }
            Ok(())
        }
        HubKeyAction::Revoke { key_id } => {
            let revoked = repo.revoke(key_id).await?;
            if revoked {
                info!(key_id, "API key revoked");
                println!("Key '{key_id}' revoked.");
                println!("Note: the running hub may keep serving this key for up to 60s");
                println!("(verified-key cache TTL). Restart the hub to revoke immediately.");
            } else {
                println!("Key '{key_id}' not found or already revoked.");
            }
            Ok(())
        }
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        let cut: String = value.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_selection_requires_exactly_one() {
        // All none -> error.
        let err = Role::from_action(&HubKeyAction::Create {
            agent: None,
            hostname: None,
            app: None,
            dashboard: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("exactly one"), "{err}");

        // Two -> error.
        let err = Role::from_action(&HubKeyAction::Create {
            agent: Some("a".into()),
            hostname: None,
            app: Some("b".into()),
            dashboard: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("exactly one"), "{err}");

        // Agent role with defaults.
        let role = Role::from_action(&HubKeyAction::Create {
            agent: Some("ecom-01".into()),
            hostname: None,
            app: None,
            dashboard: None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(role.agent_id.as_deref(), Some("ecom-01"));
        assert_eq!(role.hostname.as_deref(), Some("ecom-01"));
        assert!(role.permissions.contains(&"ingest:metrics".to_string()));

        // App role.
        let role = Role::from_action(&HubKeyAction::Create {
            agent: None,
            hostname: None,
            app: Some("globalware".into()),
            dashboard: None,
        })
        .unwrap()
        .unwrap();
        assert_eq!(role.app_name.as_deref(), Some("globalware"));
        assert_eq!(role.permissions, vec!["ingest:events"]);

        // Dashboard role.
        let role = Role::from_action(&HubKeyAction::Create {
            agent: None,
            hostname: None,
            app: None,
            dashboard: Some("ws-laptop".into()),
        })
        .unwrap()
        .unwrap();
        assert!(role.agent_id.is_none() && role.app_name.is_none());
        assert_eq!(role.permissions, vec!["read:dashboard"]);
    }

    #[test]
    fn role_from_list_actions_is_none() {
        assert!(Role::from_action(&HubKeyAction::List).unwrap().is_none());
        assert!(
            Role::from_action(&HubKeyAction::Revoke {
                key_id: "a1b2c3d4".into()
            })
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn truncate_shortens() {
        assert_eq!(truncate("short", 20), "short");
        assert_eq!(truncate("0123456789012345678901", 20).chars().count(), 20);
    }
}
