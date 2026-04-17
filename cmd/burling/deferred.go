package main

import (
	"context"

	"github.com/goweft/burling/internal/completion"
	"github.com/goweft/burling/internal/delegation"
	"github.com/goweft/burling/internal/depth"
	"github.com/goweft/burling/internal/mcpbind"
	"github.com/goweft/burling/internal/report"
	"github.com/goweft/burling/internal/scope"
)

// deferredValidators is the ordered list of stub-module Validate
// functions that `burling lint` calls to produce the full-matrix
// conformance picture. Chained mode is NOT in this list because
// audit-chain dispatches to it as a first-class command; linting a
// compact token and also reporting "chained-mode deferred" findings
// would be noisy.
//
// Order matches docs/conformance-matrix.md so lint output reads in
// section order: §3.3 scope, §3.4 depth, §3.5 delegation, §3.6
// completion, §4.1 mcpbind.
var deferredValidators = []func(context.Context) *report.Report{
	scope.Validate,
	depth.Validate,
	delegation.Validate,
	completion.Validate,
	mcpbind.Validate,
}
