# Witness

A Switch room where no agent can say "done" on its own word.

Coding agents report "tests pass" when they ran nothing, ran a slice, or kept editing after the last run.
Existing checkers (groundtruth, CI gates, local stop hooks) run on one machine and show the result to one person.
Witness moves the check into the team room: the builder agent posts a receipt, a second agent from a different
vendor re-runs it on its own machine, and a human accepts or rejects in the same thread. The whole exchange is
in the room's history and Decisions.

## Why Switch is central

Remove Switch and the idea collapses. The point is two agents from different providers (for example Claude Code
and Codex) on different machines, plus the people who own the work, sharing one room. Switch is the only
piece that puts them there. The room template in `templates/witness-room.template.yaml` creates both agents,
the room, the rules and the kickoff message.

## How it works

1. Builder commits, pushes and runs `python3 witness/witness.py receipt --claim "..." -- <check>`.
2. The receipt records the command, exit code, last 25 lines of output (redacted) and a hash of every
   non-ignored file. It is posted to the room.
3. Witness checks out the pushed commit and pipes the block to `witness.py verify -`. Verdicts:
   - HOLDS: same files, same command, same exit code.
   - STALE: the files differ from those the receipt was taken on, so the claim says nothing about this code.
   - FALSE: the result did not reproduce.
4. A human replies `accepted <id>`. Without it the work is not finished.

## Gaps in existing tools, and what Witness does about them

| Gap | Witness |
| --- | --- |
| Result is true of an old tree, agent edited afterwards | Receipt is bound to a file hash, STALE otherwise |
| Same model checks itself | Template expects two different providers |
| Verification result lives on one laptop | It lives in the shared room and Decisions |
| Output pasted into chat leaks keys or personal data | Redactor runs before the block exists, refuses secrets in commands |

Not solved yet: a check that is itself too weak (a test with no assertions). See "Future scope".

## Run it

Needs Python 3.9 or newer. No packages.

    python3 -m unittest discover -s tests
    python3 witness/witness.py receipt --claim "unit tests pass" -- python3 -m unittest
    python3 witness/witness.py verify .witness/<id>.json

With Switch: install Switch Console, ask switch-buddy to create a room from
`templates/witness-room.template.yaml`, set the two agents to different providers, copy `witness/` into the repo.

## Demo

REPLACE_WITH_DEMO_VIDEO_LINK

## Privacy and safety

No network calls, no telemetry, standard library only. See PRIVACY.md, TERMS.md and SECURITY.md (includes the
threat model and what Witness does not defend against).

## Future scope

Mutation check (revert the change and confirm the test fails), per-repo check profiles, a Switch Core
extension that writes receipts directly into Decisions, Windows path handling.

## Tracks

Business workflow, personal or creative workflow, Best Blog, Code with Wispr.
