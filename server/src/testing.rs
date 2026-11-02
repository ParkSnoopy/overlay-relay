//! Test-only assertion macros. They return `Err` instead of panicking, so test
//! functions that return `Result` stay clean under `panic_in_result_fn`.

/// Returns `Err` with the formatted message when `condition` is false.
macro_rules! ensure {
    ($condition:expr, $($message:tt)+) => {
        if !($condition) {
            return Err(std::io::Error::other(format!($($message)+)).into());
        }
    };
    ($condition:expr $(,)?) => {
        ensure!($condition, "condition failed")
    };
}

/// Returns `Err` with both values when they differ.
macro_rules! ensure_eq {
    ($left:expr, $right:expr, $($message:tt)+) => {
        match (&$left, &$right) {
            (left, right) => {
                if left != right {
                    return Err(std::io::Error::other(format!(
                        "{}: {:?} != {:?}",
                        format_args!($($message)+),
                        left,
                        right
                    ))
                    .into());
                }
            }
        }
    };
    ($left:expr, $right:expr $(,)?) => {
        ensure_eq!($left, $right, "values differ")
    };
}
