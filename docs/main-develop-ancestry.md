# Preserve Main ancestry before a normal promotion

Before preparing a protected `develop` to `main` promotion, check that the
current Main commit is an ancestor of Develop. Equal file trees do not prove
this relationship: a previous promotion merge can leave Main with a merge
commit that Develop has not yet incorporated. The next comparison then reports
diverged branches, and the normal promotion planner correctly refuses it.

Integrate the actual current Main commit through a separate ordinary pull
request into Develop. Start from current Develop, merge Main without rebasing
or discarding accepted Develop changes, and inspect the resulting tree. Where
the merge introduces no content changes, retain both parents and explain the
ancestry prerequisite in the pull request. A human-authored integration follows
the ordinary current-revision review and product checks; it does not claim the
Release App's reviewer-free ancestry exception.

After that pull request merges and its required checks pass, read the current
protected Main and Develop tips again. Run the existing promotion planner with
those actual revisions and the currently selected native review source. Use the
hash of its fresh plan for the existing protected App preparation operation;
an earlier plan is invalid after either protected branch advances.

Keep review and CI acceptance in native GitHub history. This prerequisite does
not create a separate release-evidence package, approve the Main promotion, or
establish runtime acceptance of the GitHub Runner and its Incus test VMs.
