## Summary

Describe the problem and the smallest change that resolves it.

## Verification

List the commands run and their results.

## Evidence impact

Describe any changes to expected values, observed values, verdicts, mapping classes, or report schemas. Write `None` when not applicable.

## Checklist

- [ ] The change is scoped to an existing issue or clearly described use case.
- [ ] Tests cover new or changed behavior.
- [ ] `python -m unittest discover -s qa_tests -p "test_*.py" -v` passes.
- [ ] PowerShell files parse successfully when PowerShell code changes.
- [ ] No control treats key presence, file presence, or inventory count alone as compliance evidence.
- [ ] Inconclusive checks return `NOT_ASSESSED` rather than blaming the endpoint.
- [ ] Reports and fixtures contain no sensitive endpoint or organization data.
- [ ] Documentation and CHANGELOG are updated when user-visible behavior changes.