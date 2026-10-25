# Releasing CipherChat

One pipeline builds, checks and publishes every release, so the files on GitHub, on darkciphersystems.com and in the
source zip are the same bytes with the same SHA-256.

## 1. Build

```
powershell -ExecutionPolicy Bypass -File windows\tools\build-installers.ps1      # Setup.exe + MSI for the app, the Connector
powershell -ExecutionPolicy Bypass -File android\tools\release.ps1               # host tests, then the signed APK
sh tools/build-linux-release.sh 0.1.2                                            # the Linux server tarball (Linux or WSL)
powershell -ExecutionPolicy Bypass -File tools\release\finish-dist.ps1           # source zip, release notes, test report, SHA256SUMS
```

Everything lands in `dist\<version>\`. `finish-dist.ps1` runs the server, pentest, WebAuthn and Windows suites and adds
the Android results of the APK build; it stops unless every test passes. The source zip holds exactly the files on
`tools\public-allowlist.txt`; a file on neither that list nor `tools\private-list.txt` stops the build until someone
classifies it.

## 2. Publish

```
.\release.ps1 -DryRun        # what every step would do; changes nothing anywhere
.\release.ps1                # publish
.\release.ps1 -From website  # carry on later from a step that was pending
```

| Step | What it does | Where |
|---|---|---|
| verify | every file present, `SHA256SUMS` verifies and covers the folder, the version agrees in the MSIs, server, Android app, notes and Linux release, every test passed | local |
| sanitise | rebuilds the public copy from the source zip and runs the gates again: allowlist, no keys or certificates, every image approved by a person (`tools\approved-images.txt`), the privacy scan and gitleaks (pinned) | local |
| mirror | one commit and an annotated tag `v<version>` in the public repository, never forced; a published version is never changed | GitHub |
| release | the GitHub Release with every file; GitHub's own SHA-256 of each upload must equal ours | GitHub |
| website | checks darkciphersystems.com serves exactly the files in `release-manifest.json` (it never changes the site) | website |
| discord | checks the release card was posted in the CipherChat channel | Discord |

Every step can be run again: it finds what is already done and does only the rest. What happened is recorded in
`dist\<version>\release-state.json`.

**Kill switch:** `DCX_PUBLISH_OFF=1` (this shell) or `setx DCX_PUBLISH_OFF 1` (every new one) holds every public step
while the local ones still run.

## First release

The mirror step needs the public repository and a clone of it beside this project (`release-config.json`:
`publicRemote`, `publicClone`):

```
powershell -ExecutionPolicy Bypass -File tools\release\create-repos.ps1           # what exists, what it would do
powershell -ExecutionPolicy Bypass -File tools\release\create-repos.ps1 -Create   # create both repositories, clone the public one
```

It creates `DarkCipher0x/CipherChat` (public, the mirror) and `DarkCipher0x/CipherChat-private` (private, the working
tree), turns on secret scanning with push protection, Dependabot alerts and private vulnerability reporting, and
clones the public one to `..\CipherChat-public`. It never changes an existing repository's visibility. An empty
repository is fine: the first run adds the whole public copy as one commit. Then `.\release.ps1 -DryRun` again, and
`.\release.ps1`.

## Rules

* A published version is never replaced. A fix is a new version.
* Images are published only after a person has looked at them and their SHA-256 is in `tools\approved-images.txt`.
* The Android release key is never replaced: a new key would stop every installed copy from updating.
* Windows installers are Authenticode-signed when `DCX_SIGN_THUMBPRINT` names a code-signing certificate; until then
  the release notes say they aren't.
