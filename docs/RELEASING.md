# Releasing Astranyx

Astranyx releases are built from an existing Git tag by the Release Artifacts
workflow. Publishing a GitHub release publishes the matching distributions to
PyPI using trusted publishing. A manual workflow run builds and validates an
existing tag without publishing it to PyPI.

## Prepare a release

1. Choose a PEP 440 version and update `project.version` in `pyproject.toml`.
2. Update the version displayed in `README.md`.
3. Move the Unreleased changelog entries under the version and UTC release date.
4. Run the local release checks:

   ```bash
   python -m pip install -e '.[dev]'
   ruff check astranyx tests
   find astranyx tests -name '*.py' -type f -print0 \
     | xargs -0 -n 1 black --check --quiet
   python -m pytest -q
   python -m build
   python -m twine check dist/*
   ```

5. Install the wheel in a clean virtual environment and confirm that
   `astranyx --version` matches the candidate version.
6. Commit the release preparation and ensure CI passes on Python 3.11–3.13.

## Tag and publish

Only tag a commit after the checks above pass and the working tree is clean.
The tag must be the package version prefixed with `v`, for example:

```bash
git tag -s v4.0.0a3 -m "Astranyx 4.0.0a3"
git push origin main v4.0.0a3
```

Create and publish the corresponding GitHub release from that exact tag. The
workflow validates the tag/version match, builds the wheel and source archive,
checks package metadata, smoke-tests the installed CLI, generates SHA-256 sums,
attests the artifacts, and uploads them to GitHub and PyPI.

Do not reuse or move a published release tag. If a candidate is defective,
increment the version and prepare a new release.
