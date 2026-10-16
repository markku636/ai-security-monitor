//! 寫入 / 危險命令的確認守門（沿用 db-kit）：任何會改變系統的動作都要 `--yes`；高破壞動作再要 `--force`。
//! 未確認時回 `NeedsConfirm`，等同預演，CLI 以 exit code 2 結束。

use crate::error::{AppError, AppResult};

pub fn ensure_confirmed(yes: bool, force: bool, destructive: bool, action: &str) -> AppResult<()> {
    if !yes {
        return Err(AppError::NeedsConfirm(tf!(
            "此動作會改變系統，未執行：{action}。確認無誤請加 --yes{extra}",
            action = action,
            extra = if destructive { " --force" } else { "" }
        )));
    }
    if destructive && !force {
        return Err(AppError::NeedsConfirm(tf!(
            "此為高破壞動作，未執行：{action}。請再加 --force 確認",
            action = action
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_yes_then_force() {
        assert!(matches!(
            ensure_confirmed(false, false, false, "x"),
            Err(AppError::NeedsConfirm(_))
        ));
        assert!(ensure_confirmed(true, false, false, "x").is_ok());
        assert!(matches!(
            ensure_confirmed(true, false, true, "x"),
            Err(AppError::NeedsConfirm(_))
        ));
        assert!(ensure_confirmed(true, true, true, "x").is_ok());
    }
}
