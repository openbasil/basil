// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use super::{
    Build, EffectiveModel, MAX_JSON_DEPTH, MAX_JSON_STRING_BYTES, MAX_JSON_TOKENS, MAX_NAME_BYTES,
    MAX_PROFILES_PER_SERVICE, MAX_SERVICES, MAX_STDOUT_BYTES, MAX_VALUE_BYTES, ProjectionError,
    Service,
};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeMap;
use std::fmt;
use std::time::Instant;
use zeroize::Zeroizing;

const LIMIT_MARKER: &str = "basil-compose-model-limit";
const DEADLINE_MARKER: &str = "basil-compose-parse-deadline";
const DEADLINE_CHECK_INTERVAL: usize = 4 * 1024;

#[derive(Clone, Copy)]
struct Budget {
    deadline: Instant,
}

impl Budget {
    fn check<E: de::Error>(self) -> Result<(), E> {
        if Instant::now() >= self.deadline {
            Err(E::custom(DEADLINE_MARKER))
        } else {
            Ok(())
        }
    }
}

pub fn project_json(json: &[u8], deadline: Instant) -> Result<EffectiveModel, ProjectionError> {
    if json.len() > MAX_STDOUT_BYTES {
        return Err(ProjectionError::OutputLimit);
    }
    preflight(json, deadline)?;
    let budget = Budget { deadline };
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    let model = ModelSeed { budget }
        .deserialize(&mut deserializer)
        .map_err(|error| map_error(&error))?;
    deserializer.end().map_err(|error| map_error(&error))?;
    if Instant::now() >= deadline {
        return Err(ProjectionError::Timeout);
    }
    Ok(model)
}

fn preflight(json: &[u8], deadline: Instant) -> Result<(), ProjectionError> {
    let mut depth = 0_usize;
    let mut tokens = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut string_start = 0_usize;
    let mut scalar_bytes = 0_usize;

    for (index, byte) in json.iter().copied().enumerate() {
        if index % DEADLINE_CHECK_INTERVAL == 0 && Instant::now() >= deadline {
            return Err(ProjectionError::Timeout);
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
                if index.saturating_sub(string_start) > MAX_JSON_STRING_BYTES {
                    return Err(ProjectionError::ModelLimit);
                }
            }
            continue;
        }

        match byte {
            b'"' => {
                scalar_bytes = 0;
                in_string = true;
                string_start = index.saturating_add(1);
                tokens = tokens.saturating_add(1);
            }
            b'{' | b'[' => {
                scalar_bytes = 0;
                depth = depth.saturating_add(1);
                tokens = tokens.saturating_add(1);
                if depth > MAX_JSON_DEPTH {
                    return Err(ProjectionError::ModelLimit);
                }
            }
            b'}' | b']' => {
                scalar_bytes = 0;
                depth = depth.saturating_sub(1);
                tokens = tokens.saturating_add(1);
            }
            b',' | b':' => {
                scalar_bytes = 0;
                tokens = tokens.saturating_add(1);
            }
            byte if byte.is_ascii_whitespace() => scalar_bytes = 0,
            _ => {
                scalar_bytes = scalar_bytes.saturating_add(1);
                if scalar_bytes > MAX_JSON_STRING_BYTES {
                    return Err(ProjectionError::ModelLimit);
                }
            }
        }
        if tokens > MAX_JSON_TOKENS {
            return Err(ProjectionError::ModelLimit);
        }
    }
    if Instant::now() >= deadline {
        return Err(ProjectionError::Timeout);
    }
    Ok(())
}

fn map_error(error: &serde_json::Error) -> ProjectionError {
    let message = Zeroizing::new(error.to_string());
    if message.contains(LIMIT_MARKER) {
        ProjectionError::ModelLimit
    } else if message.contains(DEADLINE_MARKER) {
        ProjectionError::Timeout
    } else {
        ProjectionError::InvalidModel
    }
}

fn model_limit<E: de::Error>() -> E {
    E::custom(LIMIT_MARKER)
}

#[derive(Clone, Copy)]
struct StringSeed {
    max_bytes: usize,
    reject_control: bool,
    budget: Budget,
}

impl<'de> DeserializeSeed<'de> for StringSeed {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.budget.check()?;
        deserializer.deserialize_str(StringVisitor { seed: self })
    }
}

struct StringVisitor {
    seed: StringSeed,
}

impl StringVisitor {
    fn validate<E: de::Error>(&self, value: &str) -> Result<(), E> {
        self.seed.budget.check()?;
        if value.is_empty()
            || value.len() > self.seed.max_bytes
            || (self.seed.reject_control && value.chars().any(char::is_control))
        {
            return Err(model_limit());
        }
        Ok(())
    }
}

impl<'de> Visitor<'de> for StringVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded string")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.validate(value)?;
        Ok(value.to_owned())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.validate(value)?;
        Ok(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.validate(&value)?;
        Ok(value)
    }
}

struct OptionalStringSeed(StringSeed);

impl<'de> DeserializeSeed<'de> for OptionalStringSeed {
    type Value = Option<String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_option(OptionalStringVisitor(self.0))
    }
}

struct OptionalStringVisitor(StringSeed);

impl<'de> Visitor<'de> for OptionalStringVisitor {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded string or null")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.0.deserialize(deserializer).map(Some)
    }
}

struct ModelSeed {
    budget: Budget,
}

impl<'de> DeserializeSeed<'de> for ModelSeed {
    type Value = EffectiveModel;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_map(ModelVisitor {
            budget: self.budget,
        })
    }
}

struct ModelVisitor {
    budget: Budget,
}

impl<'de> Visitor<'de> for ModelVisitor {
    type Value = EffectiveModel;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Docker Compose v2 normalized JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut name = None;
        let mut services = None;
        while let Some(field) = map.next_key::<ModelField>()? {
            self.budget.check()?;
            match field {
                ModelField::Name => {
                    if name.is_some() {
                        return Err(de::Error::duplicate_field("name"));
                    }
                    name = Some(map.next_value_seed(StringSeed {
                        max_bytes: MAX_NAME_BYTES,
                        reject_control: true,
                        budget: self.budget,
                    })?);
                }
                ModelField::Services => {
                    if services.is_some() {
                        return Err(de::Error::duplicate_field("services"));
                    }
                    services = Some(map.next_value_seed(ServicesSeed {
                        budget: self.budget,
                    })?);
                }
                ModelField::Other => {
                    map.next_value_seed(SkipSeed {
                        budget: self.budget,
                    })?;
                }
            }
        }
        Ok(EffectiveModel {
            name: name.ok_or_else(|| de::Error::missing_field("name"))?,
            services: services.ok_or_else(|| de::Error::missing_field("services"))?,
        })
    }
}

enum ModelField {
    Name,
    Services,
    Other,
}

impl<'de> serde::Deserialize<'de> for ModelField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_identifier(ModelFieldVisitor)
    }
}

struct ModelFieldVisitor;

impl Visitor<'_> for ModelFieldVisitor {
    type Value = ModelField;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an effective-model field")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(match value {
            "name" => ModelField::Name,
            "services" => ModelField::Services,
            _ => ModelField::Other,
        })
    }
}

struct ServicesSeed {
    budget: Budget,
}

impl<'de> DeserializeSeed<'de> for ServicesSeed {
    type Value = BTreeMap<String, Service>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_map(ServicesVisitor {
            budget: self.budget,
        })
    }
}

struct ServicesVisitor {
    budget: Budget,
}

impl<'de> Visitor<'de> for ServicesVisitor {
    type Value = BTreeMap<String, Service>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded service map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut services = BTreeMap::new();
        loop {
            self.budget.check()?;
            if services.len() == MAX_SERVICES {
                if map.next_key::<IgnoredAny>()?.is_some() {
                    return Err(model_limit());
                }
                break;
            }
            let Some(name) = map.next_key_seed(StringSeed {
                max_bytes: MAX_NAME_BYTES,
                reject_control: true,
                budget: self.budget,
            })?
            else {
                break;
            };
            let service = map.next_value_seed(ServiceSeed {
                budget: self.budget,
            })?;
            if services.insert(name, service).is_some() {
                return Err(de::Error::custom("duplicate service"));
            }
        }
        Ok(services)
    }
}

struct ServiceSeed {
    budget: Budget,
}

impl<'de> DeserializeSeed<'de> for ServiceSeed {
    type Value = Service;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_map(ServiceVisitor {
            budget: self.budget,
        })
    }
}

struct ServiceVisitor {
    budget: Budget,
}

impl<'de> Visitor<'de> for ServiceVisitor {
    type Value = Service;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a normalized service object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut image = Slot::Unset;
        let mut platform = Slot::Unset;
        let mut profiles = None;
        let mut build = None;
        while let Some(field) = map.next_key::<ServiceField>()? {
            self.budget.check()?;
            match field {
                ServiceField::Image => {
                    set_optional_string(&mut image, &mut map, "image", self.budget)?;
                }
                ServiceField::Platform => {
                    set_optional_string(&mut platform, &mut map, "platform", self.budget)?;
                }
                ServiceField::Profiles => {
                    if profiles.is_some() {
                        return Err(de::Error::duplicate_field("profiles"));
                    }
                    profiles = Some(map.next_value_seed(ProfilesSeed {
                        budget: self.budget,
                    })?);
                }
                ServiceField::Build => {
                    if build.is_some() {
                        return Err(de::Error::duplicate_field("build"));
                    }
                    build = Some(map.next_value_seed(OptionalBuildSeed {
                        budget: self.budget,
                    })?);
                }
                ServiceField::Other => {
                    map.next_value_seed(SkipSeed {
                        budget: self.budget,
                    })?;
                }
            }
        }
        Ok(Service {
            image: image.into_option().unwrap_or(None),
            platform: platform.into_option().unwrap_or(None),
            profiles: profiles.unwrap_or_default(),
            build: build.unwrap_or(None),
        })
    }
}

fn set_optional_string<'de, A>(
    destination: &mut Slot<Option<String>>,
    map: &mut A,
    field: &'static str,
    budget: Budget,
) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
{
    if destination.is_set() {
        return Err(de::Error::duplicate_field(field));
    }
    *destination = Slot::Set(map.next_value_seed(OptionalStringSeed(StringSeed {
        max_bytes: MAX_VALUE_BYTES,
        reject_control: false,
        budget,
    }))?);
    Ok(())
}

enum Slot<T> {
    Unset,
    Set(T),
}

impl<T> Slot<T> {
    const fn is_set(&self) -> bool {
        matches!(self, Self::Set(_))
    }

    fn into_option(self) -> Option<T> {
        match self {
            Self::Unset => None,
            Self::Set(value) => Some(value),
        }
    }
}

enum ServiceField {
    Image,
    Platform,
    Profiles,
    Build,
    Other,
}

impl<'de> serde::Deserialize<'de> for ServiceField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_identifier(ServiceFieldVisitor)
    }
}

struct ServiceFieldVisitor;

impl Visitor<'_> for ServiceFieldVisitor {
    type Value = ServiceField;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a normalized service field")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(match value {
            "image" => ServiceField::Image,
            "platform" => ServiceField::Platform,
            "profiles" => ServiceField::Profiles,
            "build" => ServiceField::Build,
            _ => ServiceField::Other,
        })
    }
}

struct ProfilesSeed {
    budget: Budget,
}

impl<'de> DeserializeSeed<'de> for ProfilesSeed {
    type Value = Vec<String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_seq(ProfilesVisitor {
            budget: self.budget,
        })
    }
}

struct ProfilesVisitor {
    budget: Budget,
}

impl<'de> Visitor<'de> for ProfilesVisitor {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded profile array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut profiles = Vec::new();
        loop {
            self.budget.check()?;
            if profiles.len() == MAX_PROFILES_PER_SERVICE {
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(model_limit());
                }
                break;
            }
            let Some(profile) = sequence.next_element_seed(StringSeed {
                max_bytes: MAX_NAME_BYTES,
                reject_control: true,
                budget: self.budget,
            })?
            else {
                break;
            };
            profiles.push(profile);
        }
        Ok(profiles)
    }
}

struct OptionalBuildSeed {
    budget: Budget,
}

impl<'de> DeserializeSeed<'de> for OptionalBuildSeed {
    type Value = Option<Build>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_option(OptionalBuildVisitor {
            budget: self.budget,
        })
    }
}

struct OptionalBuildVisitor {
    budget: Budget,
}

impl<'de> Visitor<'de> for OptionalBuildVisitor {
    type Value = Option<Build>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a build object, context string, or null")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer
            .deserialize_any(BuildVisitor {
                budget: self.budget,
            })
            .map(Some)
    }
}

struct BuildVisitor {
    budget: Budget,
}

impl BuildVisitor {
    fn context<E: de::Error>(self, value: &str) -> Result<Build, E> {
        let visitor = StringVisitor {
            seed: StringSeed {
                max_bytes: MAX_VALUE_BYTES,
                reject_control: false,
                budget: self.budget,
            },
        };
        visitor.validate(value)?;
        Ok(Build {
            context: Some(value.to_owned()),
            dockerfile: None,
        })
    }
}

impl<'de> Visitor<'de> for BuildVisitor {
    type Value = Build;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded build object or context string")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.context(value)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.context(value)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut context = Slot::Unset;
        let mut dockerfile = Slot::Unset;
        while let Some(field) = map.next_key::<BuildField>()? {
            self.budget.check()?;
            match field {
                BuildField::Context => {
                    set_optional_string(&mut context, &mut map, "context", self.budget)?;
                }
                BuildField::Dockerfile => {
                    set_optional_string(&mut dockerfile, &mut map, "dockerfile", self.budget)?;
                }
                BuildField::Other => {
                    map.next_value_seed(SkipSeed {
                        budget: self.budget,
                    })?;
                }
            }
        }
        Ok(Build {
            context: context.into_option().unwrap_or(None),
            dockerfile: dockerfile.into_option().unwrap_or(None),
        })
    }
}

enum BuildField {
    Context,
    Dockerfile,
    Other,
}

impl<'de> serde::Deserialize<'de> for BuildField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_identifier(BuildFieldVisitor)
    }
}

struct BuildFieldVisitor;

impl Visitor<'_> for BuildFieldVisitor {
    type Value = BuildField;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a normalized build field")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(match value {
            "context" => BuildField::Context,
            "dockerfile" => BuildField::Dockerfile,
            _ => BuildField::Other,
        })
    }
}

struct SkipSeed {
    budget: Budget,
}

impl<'de> DeserializeSeed<'de> for SkipSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.budget.check()?;
        deserializer.deserialize_any(SkipVisitor {
            budget: self.budget,
        })
    }
}

struct SkipVisitor {
    budget: Budget,
}

impl SkipVisitor {
    fn checked<E: de::Error>(self) -> Result<(), E> {
        self.budget.check()
    }
}

impl<'de> Visitor<'de> for SkipVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any directly skipped JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.checked()
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.checked()
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.checked()
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.checked()
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.checked()
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.checked()
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.checked()
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.checked()
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.checked()
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        SkipSeed {
            budget: self.budget,
        }
        .deserialize(deserializer)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        SkipSeed {
            budget: self.budget,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(SkipSeed {
                budget: self.budget,
            })?
            .is_some()
        {}
        self.budget.check()
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(SkipSeed {
                budget: self.budget,
            })?;
        }
        self.budget.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn expired_deadline_rejects_before_deserialization() {
        let deadline = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("past instant");
        assert!(matches!(
            project_json(br#"{"name":"p","services":{}}"#, deadline),
            Err(ProjectionError::Timeout)
        ));
    }
}
