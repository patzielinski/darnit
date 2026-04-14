# darnit-gittuf

Gittuf policy checks plugin for darnit.

Provides three controls:
- GT-01.01 GittufInitialized — checks refs/gittuf/policy exists
- GT-01.02 GittufPolicyValid — runs gittuf verify-ref HEAD
- GT-02.01 CommitsSigned — checks last 5 commits are cryptographically signed