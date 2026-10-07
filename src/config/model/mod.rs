pub mod app;
pub mod dns;
pub mod notification;
pub mod provider;
pub(crate) mod provider_mask;

pub use app::*;
pub use dns::*;
pub use notification::*;
pub use provider::*;

/// 敏感凭据在回传前端时的统一脱敏掩码 (P1-5)
pub const CREDENTIAL_MASK: &str = "******";

#[inline]
pub(crate) fn mask_str(s: &mut String) {
    if !s.is_empty() {
        *s = CREDENTIAL_MASK.to_string();
    }
}

#[inline]
pub(crate) fn mask_opt(s: &mut Option<String>) {
    if let Some(val) = s.as_ref()
        && !val.is_empty()
    {
        *s = Some(CREDENTIAL_MASK.to_string());
    }
}

#[inline]
pub(crate) fn restore_str(target: &mut String, old: &str) {
    if target == CREDENTIAL_MASK {
        *target = old.to_string();
    }
}

#[inline]
pub(crate) fn restore_opt(target: &mut Option<String>, old: &Option<String>) {
    match target.as_deref() {
        Some(CREDENTIAL_MASK) => {
            *target = old.clone();
        }
        Some(val) if val.trim().is_empty() => {
            *target = None;
        }
        _ => {}
    }
}
