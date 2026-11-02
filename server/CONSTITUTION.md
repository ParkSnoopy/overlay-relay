# Project Constitution

## Authority and scope

Follow [Google's Rust Style Guide](https://google.github.io/styleguide/rustguide.html), supplemented by the [Rust Style Guide](https://doc.rust-lang.org/style-guide/) and [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
The profile overrides below take precedence where this profile intentionally differs from Google.
Apply API design rules to reusable libraries; favor simplicity and directness over speculative generalization in applications.
Chromium-only crate layouts, import mechanisms, async restrictions, and thread restrictions do not apply outside Chromium.
Fuchsia-only mutex and test-framework requirements do not apply outside Fuchsia.

The selected profile's `lint.toml` defines automated lint levels in Cargo.toml.
Its `clippy.toml` configures thresholds only for enabled lints.
Design guidance also requires review; passing Clippy does not prove compliance with this constitution or absence of panics.

## Code organization and imports

- Name leaf modules and source files after their primary user-defined item when one exists.
- Keep non-leaf modules focused on module declarations and re-exports, with only small amounts of coordinating implementation when needed.
- Avoid glob imports, except for inline-module `super::*`, enum-focused local imports, non-leaf re-exports, and justified framework or C++ interop cases permitted by Google.
- Import items from one module per `use` statement; avoid nested module paths inside grouped imports.
- Prefer function-local trait imports unless the trait is used extensively throughout the file.
- Qualify external free-function calls with their module, subject to Google's disambiguation and codebase-specific exceptions.
- Import type names and use them unqualified, except where ambiguity, large type families, macros, generated code, or very large import blocks justify qualification.

## Formatting and naming

- Use the codebase's Rust formatting tool and configuration; Google's default maximum line width is 100 columns.
- Use lowercase hexadecimal literals and escapes for invisible characters where supported by the formatting setup.
- Use `#[rustfmt::skip]` only for justified manual alignment or generated code, not personal preferences.
- Use meaningful names and avoid unfamiliar abbreviations.
- Give type lifetimes descriptive names; anonymous or short local relationship lifetimes are fine where clear.
- Give generic parameters short names related to what they represent; `T` and `U` are fine for unconstrained types.
- Name constructors `new()` or `new_with_foo()`, and fallible constructors `try_new()`.
- Follow standard `as_`, `to_`, and `into_` conversion conventions.

## Ownership and API inputs

- Prefer unique ownership and borrowing over `Rc` and `Arc`, unless borrowing would make the design unreasonably complex.
- Clone when ownership genuinely requires a copy, not merely to avoid understanding borrowing.
- Accept flexible immutable references: `&T`, `&[T]`, `&str`, and `Option<&T>` rather than references to their owning wrappers.
- Prefer iterator inputs and outputs in highly reusable libraries when callers only need iteration.
- Use slices and owned collections in applications when they make the actual use case simpler.
- Consider `impl Into<T>` for library call-site ergonomics, balanced against generic complexity and code size; almost never use it for application parameters.
- Prefer enums over boolean parameters when the argument's purpose would otherwise be unclear.
- Prefer named fields over tuples or multi-field tuple structs, except in clear local contexts; single-field newtypes are fine.
- Use newtypes for distinct semantics, type safety, independent APIs, or future representation changes.

## Errors and implementation clarity

- Use `Option` for anticipated absence or simple failure whose cause is obvious.
- Use `Result` for recoverable failures where callers need context, especially I/O and network failures.
- Prefer pattern matching over checking a value and then unwrapping it.
- Add explicit types where generic returns or complex iterator chains make inference hard to follow.
- Prefer direct loops over long or stateful iterator chains; keep short, expressive combinators such as `any()`.
- Bind complex iterator chains to a named variable before using them in a `for` header.
- Give assertions useful context rather than repeating their condition.
- Do not rely on `panic::catch_unwind` for correctness; Google's narrow defense-in-depth exception requires an unwinding runtime and efforts to avoid panics.
- Prefer `format!` or `write!` for substitutions and concatenating more than two strings.

## Traits and public APIs

- Implement standard traits instead of equivalent custom methods; use `#[derive]` when it expresses the implementation.
- Anticipate trait needs in foundational libraries; add implementations as needed in applications.
- Define traits for generic programming, trait-based interfaces, or justified extension methods, not merely to organize code.
- Prefer generic parameters over `dyn Trait` in libraries unless code size or the required dispatch model warrants trait objects.
- Name extension traits with an `Ext` suffix; normally the original type's team should own them.
- Implement `Copy`, `Clone`, `Default`, comparison, and hashing traits when their semantics fit; do not promise total ordering or future copyability without justification.
- Pair important `From` implementations with discoverable inherent constructors, and implement `Default` for options structs.
- Follow Google's accessor naming conventions, and provide `is_empty()` with `len()`.
- Use `#[non_exhaustive]` on cross-team public enums and public-field structs unless their shape is stable or breakage will be coordinated; preserve struct-update use cases where needed.
- List known variants when matching non-exhaustive enums, or use `if let` / `let ... else` when only specific variants matter.
- Use `#[must_use]` for meaningful return values and lazy/error types where ignoring the value would be incorrect; avoid redundant annotations on functions returning already annotated types.
- Treat other teams' `#[doc(hidden)]` items as private.
- Make public functions `const` only when that commitment can be maintained.
- Use operator overloading for its mathematical or logical meaning, not unrelated shorthand.

## Safety, concurrency, and macros

- Use safe Rust whenever it can provide the required functionality.
- Where the profile permits necessary unsafe code, isolate it behind safe abstractions, document invariants with `SAFETY:` comments, and justify why safe code cannot suffice.
- Back performance-based unsafe justifications with benchmarks.
- Do not use unstable language features without an applicable codebase-approved exception.
- Never recover protected data from a poisoned mutex.
- Prefer ordinary Rust APIs over macros and code generation; prefer simple `macro_rules!` macros over more complex generation when a macro is justified.
- Do not arrange for code to run before `main()`.

## Documentation and testing

- Document public APIs, relevant failure behavior, panic conditions, and unsafe invariants without merely repeating names or explaining Rust syntax.
- Include enough examples to show how a library is used; self-explanatory enum variants need not each have documentation.
- Use `///` for items, `//!` for modules and crates, Markdown formatting, and ordinary comments for implementation notes.
- Use the owning codebase's test framework; ordinary Cargo projects may use `#[test]` and integration tests under `tests/`.
- Test meaningful behavior and failure paths, not only happy paths.

## Minimal profile overrides

All profiles retain these minimal guardrails:

- Do not call `unwrap()`, `expect()`, or `panic!()`; handle missing values and recoverable errors explicitly.
- Google permits invariant panics and prefers `expect()` when one is necessary; these profiles intentionally impose stricter restrictions on those constructs.
- Do not add `#[allow(...)]` to silence lint findings, even where Google permits a documented exception.
- Do not leave `dbg!()` calls or `todo!()` placeholders.
- These checks do not ban every possible panic source or enable every Google-related Clippy lint.

## Standard profile additions

- Apply the minimal profile overrides above.
- Enable Clippy's pedantic group as warnings, with the explicit relaxations in `lint.toml`.
- Do not panic in functions returning `Result` or leave `unimplemented!()` placeholders.
- Use structured logging or explicit writers instead of `println!()` and `eprintln!()`.
- Do not hold synchronous lock guards across `.await` or call `std::process::exit()`.
- Documentation, meaningful return values, and readable functions still need review where `missing_errors_doc`, `missing_panics_doc`, `doc_markdown`, `must_use_candidate`, `module_name_repetitions`, `similar_names`, and `too_many_lines` are allowed.

## Maximum profile overrides and additions

- Apply the standard additions above, except for the lint levels and relaxations replaced here.
- Forbid unsafe code entirely, even where Google's general guidance permits a justified unsafe abstraction.
- Forbid non-ASCII identifiers.
- Deny Rust warnings, Rust 2018 idiom violations, future-incompatible patterns, and nonstandard style.
- Deny missing public API documentation, missing `Debug` and `Copy` implementations flagged by Rust, and unfulfilled lint expectations.
- Deny all rustdoc lints and enable Clippy's `all`, `pedantic`, `nursery`, and `cargo` groups at deny level.
- Do not bypass destructors with `std::mem::forget()`; address oversized futures, stack arrays, and types passed by value when flagged.
- The standard profile's lint relaxations do not carry over: only `multiple_crate_versions`, `cast_possible_truncation`, `cast_sign_loss`, `cast_precision_loss`, `cast_possible_wrap`, and `cognitive_complexity` are explicitly allowed here.
- The cognitive-complexity threshold does not enable its disabled lint; other design guidance still requires review.
