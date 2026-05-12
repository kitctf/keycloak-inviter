use crate::error::WebError;
use crate::server::AuthedUser;
use axum::{Extension, Json};
use rootcause::Report;
use rootcause::option_ext::OptionExt;
use rootcause::prelude::ResultExt;
use serde::{Deserialize, Deserializer, Serialize};

const APPS_TEMPLATE: &str = include_str!("../../assets/roles_mapping.yaml");

pub async fn get_available_applications(
    Extension(caller): Extension<AuthedUser>,
) -> Result<Json<Vec<JsonAllowdKitctfService>>, WebError> {
    let all_services = parse_apps_template().context("failed to parse applications")?;

    let allowed_services = all_services
        .get_allowed(&caller)
        .context("failed to get allowed applications")?
        .into_iter()
        .map(JsonAllowdKitctfService::from)
        .collect();

    Ok(Json(allowed_services))
}

fn parse_apps_template() -> Result<KitctfServices, Report> {
    let services: KitctfServices =
        serde_yaml::from_str(APPS_TEMPLATE).context("failed to parse applications template")?;
    Ok(services)
}

#[derive(Debug, Deserialize)]
struct KitctfServices {
    services: Vec<KitctfService>,
}

impl KitctfServices {
    pub fn get_allowed(self, user: &AuthedUser) -> Result<Vec<KitctfService>, Report> {
        let mut allowed: Vec<KitctfService> = Vec::new();
        for service in self.services {
            for claim in &service.token_claims {
                let matches = claim
                    .matches(&user.access_token_content)
                    .context("failed to evaluate rule for service")
                    .attach(format!("service: {}", service.name))?;
                if matches {
                    allowed.push(service.clone());
                    break;
                }
            }
        }
        Ok(allowed)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct KitctfService {
    name: String,
    url: String,
    icon: Option<String>,
    #[serde(rename = "group")]
    _group: String,
    token_claims: Vec<KitctfTokenClaim>,
}

#[derive(Debug, Clone)]
struct KitctfTokenClaim {
    needle: String,
    haystack: Vec<String>,
}

impl<'de> Deserialize<'de> for KitctfTokenClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let as_str = String::deserialize(deserializer)?;
        let (needle, haystack) = as_str
            .split_once(" in ")
            .context("token rule did not contain ' in '")
            .map_err(serde::de::Error::custom)?;
        let haystack = haystack.split(".").map(|it| it.to_string()).collect();

        Ok(Self {
            needle: needle.to_string(),
            haystack,
        })
    }
}

impl KitctfTokenClaim {
    pub fn matches(&self, user_obj: &serde_json::Value) -> Result<bool, Report> {
        let mut current = user_obj;
        for next in &self.haystack {
            let Some(next) = current.get(next) else {
                return Ok(false);
            };
            current = next;
        }
        let current = current
            .as_array()
            .context("malformed rule, did not arrive at array")
            .attach(format!("needle: {}", self.needle))
            .attach(format!("rule: {:?}", self.haystack))?;
        let items = current
            .iter()
            .map(|it| {
                it.as_str()
                    .context("malformed rule, final array did not contain string")
            })
            .collect::<Result<Vec<&str>, Report<&str>>>()?;

        Ok(items.contains(&self.needle.as_str()))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonAllowdKitctfService {
    name: String,
    url: String,
    icon: Option<String>,
}

impl From<KitctfService> for JsonAllowdKitctfService {
    fn from(value: KitctfService) -> Self {
        Self {
            name: value.name,
            url: value.url,
            icon: value.icon,
        }
    }
}
