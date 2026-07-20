# Contributing to SSH Honeypot

## Getting Started
- Fork the repository and clone your fork.
- Create a feature branch (`git checkout -b feature/my-feature`).
- Install dependencies: `pip install -r requirements.txt`.

## Development Guidelines
- Follow PEP 8 style conventions.
- Write tests for new features in the `tests/` directory.
- Run existing tests with `pytest` before submitting.
- Update `README.md` if adding or changing user-facing functionality.
- Keep configuration defaults backward-compatible.

## Commit Messages
- Use conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`.
- Explain the *why* behind the change, not just the *what*.

## Pull Requests
- Keep PRs focused on a single concern.
- Reference any related issues in the description.
- Ensure all CI checks pass before requesting review.
