//! 下游擴充點：私有 overlay 可在此注入自家字串的英文譯文。上游恆回 `None`。

pub fn lookup(_zh: &str) -> Option<&'static str> {
    None
}
