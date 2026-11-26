//! Translate a user-selected model route into one broker decision.

use std::collections::BTreeMap;

use abyss_sdk::plugin::{AgentRequestContext, ModifyAction, RequestDecision};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::catalog::{Catalog, ListedModel, ModelListRequest, Selection};

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Routes {
    catalog: Catalog,
    selections: BTreeMap<String, Selection>,
}

#[derive(Deserialize, Serialize)]
pub struct Select {
    pub harness: String,
    pub selection: Option<Selection>,
}

fn http_operation(
    context: &AgentRequestContext,
    authority: &str,
    path: &str,
) -> Option<&'static str> {
    if !context
        .server_name
        .as_deref()?
        .eq_ignore_ascii_case(authority)
    {
        return None;
    }
    let operation = match path {
        "/responses" | "/v1/responses" | "/backend-api/codex/responses" => "responses",
        "/chat/completions" | "/v1/chat/completions" => "chat/completions",
        "/messages" | "/v1/messages" | "/anthropic/v1/messages" => "messages",
        _ => return None,
    };
    let upgrade = operation == "responses"
        && context.method == "GET"
        && context.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("upgrade") && value.eq_ignore_ascii_case("websocket")
        });
    (upgrade || (context.method == "POST" && context.model_writable)).then_some(operation)
}

impl Routes {
    pub async fn list_models(
        &self,
        request: &ModelListRequest,
    ) -> Result<Vec<ListedModel>, &'static str> {
        self.catalog.list_models(request).await
    }

    pub fn snapshot(&self) -> Result<Value, &'static str> {
        Ok(json!({"catalog": self.catalog.choices()?, "selections": self.selections}))
    }

    pub fn load(&mut self, catalog: Catalog) -> Result<Value, &'static str> {
        let choices = catalog.choices()?;
        self.selections.retain(|harness, selection| {
            self.catalog
                .resolve(harness, selection)
                .ok()
                .zip(catalog.resolve(harness, selection).ok())
                .is_some_and(|(old, new)| old.base_url == new.base_url)
        });
        let response = json!({"catalog":choices,"selections":self.selections});
        self.catalog = catalog;
        Ok(response)
    }

    pub fn select(&mut self, update: Select) -> Result<Value, &'static str> {
        if let Some(selection) = update.selection {
            self.catalog.resolve(&update.harness, &selection)?;
            self.selections.insert(update.harness, selection);
        } else {
            self.selections.remove(&update.harness);
        }
        self.snapshot()
    }

    /// Each selected model call gets its provider destination and credential.
    /// Connection-bound authentication is sent on the upgrade, then frames can edit the model.
    pub fn inspect(&self, context: &AgentRequestContext) -> RequestDecision {
        self.decision(context).unwrap_or(RequestDecision::Allow)
    }

    fn decision(&self, context: &AgentRequestContext) -> Option<RequestDecision> {
        let harness = &context.harness.as_ref()?.id;
        let route = self
            .catalog
            .resolve(harness, self.selections.get(harness)?)
            .ok()?;
        let endpoint = crate::catalog::https_url(route.base_url).ok()?;
        let host = endpoint.host_str()?;
        let authority = context.authority.as_deref()?;
        let path = context.path.split('?').next()?;
        if context.websocket {
            // An established Responses socket stays on the host selected during its upgrade.
            return (authority.eq_ignore_ascii_case(host)
                && context.model_writable
                && path.ends_with("/responses"))
            .then(|| {
                RequestDecision::Modify(Box::new([ModifyAction::SetModel(route.model.to_owned())]))
            });
        }
        let operation = http_operation(context, authority, path)?;
        if !context.auth_token_writable {
            return Some(RequestDecision::Block(
                "Model routing requires a writable API credential.".to_owned(),
            ));
        }
        let prefix = endpoint.path().trim_end_matches('/');
        let version = if operation == "messages" && !prefix.ends_with("/v1") {
            "/v1"
        } else {
            ""
        };
        let mut actions = vec![
            ModifyAction::SetUpstreamHost(host.to_owned()),
            ModifyAction::SetRequestPath(format!("{prefix}{version}/{operation}")),
            if route.bearer {
                ModifyAction::SetBearerToken(route.authentication.to_owned())
            } else {
                ModifyAction::SetAuthToken(route.authentication.to_owned())
            },
        ];
        if let Some(proxy) = route.proxy {
            actions.push(ModifyAction::SetAccountProxy(proxy.clone()));
        }
        if context.model_writable {
            actions.push(ModifyAction::SetModel(route.model.to_owned()));
        }
        Some(RequestDecision::Modify(actions.into_boxed_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codex_call() -> AgentRequestContext {
        serde_json::from_value(json!({
            "flow_id": "flow", "request_id": "test", "ingress": "test",
            "destination": "127.0.0.1:443", "harness": {"id":"codex"},
            "path": "/v1/responses?keep=1", "authority": "chatgpt.com", "server_name": "chatgpt.com",
            "method": "POST", "headers": [], "websocket": false, "sequence": 1,
            "body": {"encoding":"utf8","content":"{}"}, "parsing_status": "parsed",
            "auth_token_writable": true, "model_writable": true
        })).unwrap()
    }

    fn snapshot(key: &str) -> Value {
        json!({
            "harness_providers": {"codex": ["missing", "other", "unresolved", "openai"]},
            "providers": {
                "openai": {"base_url": null, "credentials": {
                    "primary": {"kind": "api_key", "api_key": "fixture-unselected"}
                }},
                "unresolved": {"base_url": null, "credentials": {
                    "primary": {"kind": "api_key", "api_key": "fixture-unresolved"}
                }},
                "other": {"base_url": "https://example.org/v1", "credentials": {
                    "primary": {"kind": "api_key", "api_key": key},
                    "subscription": {"kind": "account", "login": "fixture-user", "secret": "fixture-password"}
                }}
            }
        })
    }

    #[test]
    fn service_snapshots_rotate_the_selected_key_and_revoke_removed_assignments() {
        let mut routes = Routes::default();
        let first = snapshot("fixture-first");
        let state = routes
            .load(serde_json::from_value(first.clone()).unwrap())
            .unwrap();
        assert!(!state.to_string().contains("fixture-"));
        assert_eq!(
            state["catalog"]["harness_providers"]["codex"],
            json!(["other", "openai"])
        );
        assert_eq!(
            state["catalog"]["providers"]["openai"]["base_url"],
            "https://api.openai.com/v1"
        );
        assert_eq!(state["catalog"]["providers"]["other"]["models"], json!([]));
        assert_eq!(
            state["catalog"]["providers"]["other"]["credentials"]["subscription"]["configured"],
            false
        );
        assert_eq!(serde_json::to_value(&routes).unwrap()["catalog"], first);

        let selection = json!({"provider":"other","credential":"primary","model":"model-b"});
        routes
            .select(
                serde_json::from_value(json!({"harness":"codex", "selection":selection})).unwrap(),
            )
            .unwrap();
        let rotated = snapshot("fixture-rotated");
        let state = routes
            .load(serde_json::from_value(rotated).unwrap())
            .unwrap();
        assert_eq!(state["selections"]["codex"], selection);
        routes = serde_json::from_slice(&serde_json::to_vec(&routes).unwrap()).unwrap();
        assert_eq!(
            routes.inspect(&codex_call()),
            RequestDecision::Modify(Box::new([
                ModifyAction::SetUpstreamHost("example.org".into()),
                ModifyAction::SetRequestPath("/v1/responses".into()),
                ModifyAction::SetAuthToken("fixture-rotated".into()),
                ModifyAction::SetModel("model-b".into())
            ]))
        );
        let mut unrelated = codex_call();
        unrelated.server_name = Some("different.example".into());
        assert_eq!(routes.inspect(&unrelated), RequestDecision::Allow);
        let mut frame = codex_call();
        frame.websocket = true;
        frame.authority = Some("example.org".into());
        assert_eq!(
            routes.inspect(&frame),
            RequestDecision::Modify(Box::new([ModifyAction::SetModel("model-b".into())]))
        );
        for (method, path) in [
            ("GET", "/backend-api/plugins/export/curated"),
            ("POST", "/plugins/messages"),
            ("GET", "/v1/responses"),
            ("GET", "/v1/models"),
        ] {
            let mut call = codex_call();
            call.method = method.into();
            call.path = path.into();
            assert_eq!(routes.inspect(&call), RequestDecision::Allow);
        }
        let mut upgrade = codex_call();
        upgrade.method = "GET".into();
        upgrade.model_writable = false;
        upgrade.headers.push(("upgrade".into(), "websocket".into()));
        assert_eq!(
            routes.inspect(&upgrade),
            RequestDecision::Modify(Box::new([
                ModifyAction::SetUpstreamHost("example.org".into()),
                ModifyAction::SetRequestPath("/v1/responses".into()),
                ModifyAction::SetAuthToken("fixture-rotated".into())
            ]))
        );
        let empty = json!({"harness_providers":{},"providers":{}});
        let state = routes.load(serde_json::from_value(empty).unwrap()).unwrap();
        assert_eq!(state["selections"], json!({}));
        assert_eq!(routes.inspect(&codex_call()), RequestDecision::Allow);
    }

    #[test]
    fn provider_account_with_unrepresentable_headers_is_unavailable() {
        let mut routes = Routes::default();
        let load = serde_json::from_value(json!({
            "harness_providers":{"codex":["example"]},
            "providers":{"example":{"base_url":"https://relay.example/api","credentials":{"team":{
                "kind":"account","login":"unused","secret":"unused-secret",
                "headers":{"Authorization":"Custom literal","X-Team":"team-7"}
            }}}}
        }))
        .unwrap();
        let state = routes.load(load).unwrap();
        assert!(
            !state.to_string().contains("Custom literal"),
            "catalog projections omit credential values"
        );
        assert_eq!(
            state["catalog"]["providers"]["example"]["credentials"]["team"]["configured"],
            false
        );
        assert!(routes.select(serde_json::from_value(json!({"harness":"codex","selection":{"provider":"example","credential":"team","model":"model-b"}})).unwrap()).is_err());
    }
}
