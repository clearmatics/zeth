# Contributing

When contributing to this repository, please first discuss the changes you wish to make via issue,
email, or any other method with the owners of this repository before making a change.

Please note that we have a code of conduct. Please follow it in all your interactions with the project.

## Coding Standards

Coding standards are described in full [here](CODING_STANDARDS.md).

## Pull Request Process

1. Ensure any install or build dependencies are removed from your branch before opening a Pull Request.
   Furthermore, please do make sure to extend the [.gitignore](./.gitignore) file to keep unnecessary files
   outside of the version control.
2. Update the README.md files and the relevant code comments with details of changes to the interface.
   This includes: new environment variables, exposed ports, useful file locations and container parameters for instance.
3. If the Pull Request requires a version change (e.g. a "fix" or new release), increase the version numbers in all relevant files.
   The versioning scheme we use is [SemVer][semver].
4. All Pull Requests must be reviewed by a code owner. While under review, a code owner may ask the Pull Request author to *rebase*
   her branch on top of the targeted "base" branch. If so, please be sure to *rebase* on top of the base branch (and *not merge*
   the base branch in your branch), as we strive to avoid duplicated merge commits in the git history (merging is a unidirectional
   process e.g. `master < develop < feature` or `master < hotfix`).
5. Once approved, the Pull Request is merged by one of the code owners.

## Code of Conduct

This project and everyone participating in it is governed by the [Code of Conduct][codeofconduct].
By participating, you are expected to uphold this code. Please report unacceptable behavior to [opensource@clearmatics.com][email].

[codeofconduct]: CODE_OF_CONDUCT.md
[semver]: http://semver.org/
[email]: mailto:opensource@clearmatics.com
