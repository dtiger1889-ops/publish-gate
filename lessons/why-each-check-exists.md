# Why each check exists

Most of these checks were added after something got through. This is the record of what got through and what replaced the control that missed it. The fixes only make sense next to the failures.

## A clean token scan is not a clean repo

The first gate was a list of personal words grepped over each repo. On one pass, a manual read by a second reviewer found eight leaks in repos the scan had called clean. None of them were on the list, because nobody had thought to list them. Several were example values in docs, copied from the author's own data because real data was the nearest thing to hand.

What replaced it: the scan stayed, but a publish now stops at the diff and waits for a person to read it. The scan finds the things you already know about. Only reading finds the rest. The second rule from the same day: docs describe what a value must be, never an example value taken from your own data. Examples mined from a real system are leaks by construction.

## A scan that cannot fail looks exactly like a scan that passed

A gate once ran a grep with a flag that the grep in use did not support. It exited with a usage error, the error went to a suppressed stream, and the gate read "no matches" as clean. The instructions themselves carried the bad flag, so every run that followed them passed whatever it was given.

What replaced it: every run plants known bad content first and confirms each text check catches it, and `selftest` does the same for the file checks, history and gitleaks. A missing or empty denylist, an unreadable file, a tool that crashed: each makes the run UNVERIFIABLE, exit 2, and exit 2 is never treated as a pass.

## The email in commit metadata is part of the publish

Files were clean and a personal email address still went public, twice, in the author and committer fields of commits. Rewriting published history to remove it is slow and never fully works: the hosting site keeps old commits reachable by their hash.

What replaced it: the gate refuses to run unless the repo's git email is a public address, checks every commit about to be pushed, and checks again after its own commit and before the push. Later the same leak came back through a merge done on the GitHub website, which writes commits under an email GitHub chooses. That one is now a documented rule rather than a check: merge locally, then publish.

## Scan what git ships, not what is in the folder

The folder and the commit are different things. Ignored files sit in the folder and never ship; a file can be staged in one state and edited afterwards; and history holds files the folder no longer has. A scan of the folder answers a question nobody asked.

What replaced it: the publish set is the git index, read blob by blob. History is scanned as every distinct blob reachable from the branch being pushed, so a file deleted years ago is still checked.

## A publish should not grow into an audit

A routine one-file publish more than once turned into a long re-review of the whole repo, or picked up unrelated changes that happened to be lying in the folder.

What replaced it: the scope lock. You name the paths, and the gate refuses if anything else has changed. The review covers only what changed since the last certified commit, which is pinned after each successful push. A push made without the gate moves the branch past that pin, and both `publish` and `monitor` catch it.

## The denylist is the most personal file you have

A list of every name, place and handle you never want published is, collected in one place, exactly the thing you never want published. One version of this tool kept the list inside the script, which made the script itself unpublishable.

What replaced it: the denylist lives outside every repo, the gate flags it if it ever ends up inside one, and the CI example reads it from a repository secret.

## Exemptions hide the next real hit

Clearing a false positive by exempting a word everywhere would also clear the real occurrence that turns up next month.

What replaced it: an exemption names one check, one path pattern and the text on the line, with a reason. Denylist and secret exemptions without line text are refused.

## Shared links need a preview

A public page went out without link-preview tags and every share of it unfurled as a blank card until someone noticed.

What replaced it: a site `index.html` in the publish set must carry the Open Graph and Twitter card tags.

## The first public version failed its own audit

Before release, the first build of this tool went to an independent reviewer with one instruction: find every way it could pass something it should block. It came back "not safe to publish" with thirteen blockers. A few, because they are the kind of hole any gate like this grows:

- `certify` pinned whatever the remote held without checking it, so anything pushed by hand could be blessed and then excluded from every later scan.
- On a repo that already had a remote but no certified commit, the remote's history was treated as already cleared. A key deleted years ago was never looked at.
- The commit message was written after the scan, so a personal name in `-m` went straight out.
- Two identical files, such as a pair of empty `__init__.py`, made every run report UNVERIFIABLE. The opposite failure: a deleted `.env` with the same bytes as a harmless current file was skipped, because history was deduplicated by content and the old name was never checked.
- Any file with a NUL byte counted as binary and skipped the text checks, so a UTF-16 document with your name in it passed.
- A shallow CI checkout reported its partial history as clean. LFS files, which upload their real content on push, were checked only as pointers. `push.followTags` could push tag messages nobody scanned.
- Installing gitleaks turned the built-in secret patterns off, so a key with an inline `gitleaks:allow` comment went from caught to passed.

What replaced it: each of those is now a test, and the rule behind most of them is the same as the rest of this file. A gap the gate cannot close makes the run UNVERIFIABLE rather than clean, and nothing is trusted because of where it already is.

## What larger codebases add

The original gate served small personal repos. A larger or older codebase brings risks those never had: credentials committed by many people over many years, multi-megabyte data dumps still sitting in history, phone photos with GPS tags in a docs folder, internal hostnames in config, notebooks saved with their output cells. Those are the `secret` (via gitleaks), `large-file`, `image-gps`, `internal-host`, `private-ip` and `notebook-output` checks, plus the CI and pre-push hook setup. Secret detection is delegated to gitleaks on purpose: it is maintained against hundreds of key formats, and a short pattern list written for one project is not.
