# Contributing to Astranyx

By submitting a contribution, you agree that it is provided under the Apache
License 2.0 and represent that you have the right to submit it. Do not submit
employer-owned, confidential, or third-party code without authorization.

Thank you for your interest in contributing to Astranyx.

## Project Mission

Astranyx is a mobile application security research framework designed to help researchers:

* Prioritize investigations
* Organize evidence
* Improve report quality
* Build repeatable research workflows

Astranyx is **not** a vulnerability scanner. It assists researchers in conducting structured investigations.

## Development Principles

Every contribution should:

* Solve a real research problem.
* Be well documented.
* Include tests when appropriate.
* Follow the existing project structure.

## Development Workflow

1. Create or select an issue.
2. Implement one feature or fix.
3. Test the change.
4. Update documentation if necessary.
5. Commit using a descriptive commit message.

Example commit messages:

* `feat(threat): add configurable threat rules`
* `fix(report): correct markdown generation`
* `test(review): add workspace validation test`
* `docs: update installation guide`

## Coding Style

* Keep plugins focused on a single responsibility.
* Prefer readable code over clever code.
* Avoid duplicating logic.
* Keep functions small when practical.

## Testing

Before submitting changes, run:

```bash
pytest
```

All tests should pass before opening a pull request.

## Reporting Issues

When reporting bugs, include:

* Operating system
* Python version
* Steps to reproduce
* Expected behavior
* Actual behavior
* Relevant error messages

## License

By contributing to Astranyx, you agree that your contributions will be licensed under the project's LICENSE file.
