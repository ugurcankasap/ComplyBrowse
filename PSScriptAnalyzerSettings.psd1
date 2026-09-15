@{
    Severity = @('Error', 'Warning')

    # These runners are operator-facing console tools, not reusable modules, so
    # the module-authoring style rules below do not apply to this codebase.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'                      # Console output is the product surface.
        'PSUseApprovedVerbs'                         # Internal helpers, never exported as cmdlets.
        'PSUseSingularNouns'                         # Helpers intentionally return collections.
        'PSUseShouldProcessForStateChangingFunctions' # Internal helpers take no -WhatIf/-Confirm.
        'PSReviewUnusedParameter'                    # Parameters consumed via splatting/scriptblocks.
    )
}
