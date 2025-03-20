
alias l := lint
alias p := prepare-commit

lint:
    @cargo clippy --tests -- -Dclippy::all

format:
    @cargo fmt

prepare-commit: lint format
    @echo "All checks passed"