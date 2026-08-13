package detectforge.policy.quality

default allow = false

# Rule 1: Every registered rule in manifest must have at least one true_positive sample
deny[msg] {
    some i
    rule := input.rules[i]
    count(rule.true_positive) == 0
    msg := sprintf("Rule '%s' has no true-positive samples defined.", [rule.slug])
}

# Rule 2: Every registered rule in manifest must have at least one real false_positive sample
deny[msg] {
    some i
    rule := input.rules[i]
    count(rule.false_positive) == 0
    msg := sprintf("Rule '%s' missing mandatory false-positive sample in tests/false_positive/. Boundary variants alone do not satisfy quality policy.", [rule.slug])
}

# Rule 3: Boundary variants MUST NOT satisfy false_positive check
deny[msg] {
    some i
    rule := input.rules[i]
    some j
    fp_file := rule.false_positive[j]
    contains(fp_file, "boundary_variants")
    msg := sprintf("Rule '%s' includes a boundary variant '%s' inside false_positive list. Boundary tests must remain strictly isolated in tests/boundary_variants/.", [rule.slug, fp_file])
}

# Allow if no deny rules triggered
allow {
    count(deny) == 0
}
