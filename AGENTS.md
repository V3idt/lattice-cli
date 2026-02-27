# Agent Instructions

## Core Principles

- **Do things right, not easy** - implement scalable, maintainable solutions even if they require more upfront effort.
- **Think about scalability** - consider how design and code hold up as the project grows.
- **Use existing patterns** - follow established project conventions and avoid unnecessary one-off approaches.
- **Commit after every change** - prefer small, atomic commits with descriptive messages.

## Development Guidelines

- Keep the codebase minimal and practical; avoid unnecessary complexity.
- Build for automation and agent use first (non-interactive CLI behavior, machine-readable outputs).
- Prefer deterministic behavior (stable IDs/output formats) to support reliable tooling integration.
- No emojis in code, UI, or tool output.

## Project-Specific Notes

- This project is a CLI vulnerability/security scanner focused on codebases written with AI coding tools.
- Prioritize local-first workflows and clear policy-driven findings.
- Ensure outputs are easy to integrate with other tools (for example, JSON/SARIF formats).
