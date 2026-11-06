# Security

Threat model, stated plainly.

Witness defends against an agent that is careless, hurried or wrong: one that says "tests pass" without running
them, ran only part of the suite, or kept editing after the last run. It binds each claim to a hash of every
tracked and untracked, non-ignored file and makes a second machine re-run it.

It does not defend against an agent or person who is trying to deceive you on purpose. A hostile builder can
write a test that always passes, and a hostile process on the same machine can forge a receipt. The witness
verdict is only as strong as the check command. Use a different provider for the witness and read the check.

Report vulnerabilities through GitHub private vulnerability reporting (repository Security tab, Report a vulnerability). For anything that is not a vulnerability, open a normal issue. Maintainer address for records: 299201596+triixdev@users.noreply.github.com.
