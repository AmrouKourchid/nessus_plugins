#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0021-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(214507);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-52308");

  script_name(english:"openSUSE 15 Security Update : gh (openSUSE-SU-2025:0021-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2025:0021-1 advisory.

    - Update to version 2.65.0:
      * Bump cli/go-gh for indirect security vulnerability
      * Panic mustParseTrackingRef if format is incorrect
      * Move trackingRef into pr create package
      * Make tryDetermineTrackingRef tests more respective of reality
      * Rework tryDetermineTrackingRef tests
      * Avoid pointer return from determineTrackingBranch
      * Doc determineTrackingBranch
      * Don't use pointer for determineTrackingBranch branchConfig
      * Panic if tracking ref can't be reconstructed
      * Document and rework pr create tracking branch lookup
      * Upgrade generated workflows
      * Fixed test for stdout in non-tty use case of repo fork
      * Fix test
      * Alternative: remove LocalBranch from BranchConfig
      * Set LocalBranch even if the git config fails
      * Add test for permissions check for security and analysis edits (#1)
      * print repo url to stdout
      * Update pkg/cmd/auth/login/login.go
      * Move mention of classic token to correct line
      * Separate type decrarations
      * Add mention of classic token in gh auth login docs
      * Update pkg/cmd/repo/create/create.go
      * docs(repo): make explicit which branch is used when creating a repo
      * fix(repo fork): add non-TTY output when fork is newly created
      * Move api call to editRun
      * Complete get -> list renaming
      * Better error testing for autolink TestListRun
      * Decode instead of unmarshal
      * Use 'list' instead of 'get' for autolink list type and method
      * Remove NewAutolinkClient
      * Break out autolink list json fields test
      * PR nits
      * Refactor autolink subcommands into their own packages
      * Whitespace
      * Refactor out early return in test code
      * Add testing for AutoLinkGetter
      * Refactor autolink list and test to use http interface for simpler testing
      * Apply PR comment changes
      * Introduce repo autolinks list commands
      * Remove release discussion posts and clean up related block in deployment yml
      * Extract logic into helper function
      * add pending status for workflow runs
      * Feat: Allow setting security_and_analysis settings in gh repo edit
      * Upgrade golang.org/x/net to v0.33.0
      * Document SmartBaseRepoFunc
      * Document BaseRepoFunc
      * Update releasing.md
      * Document how to set gh-merge-base

    - Update to version 2.64.0:
      * add test for different SAN and SourceRepositoryURI values
      * add test for signerRepo and tenant
      * add some more fields to test that san, sanregex are set properly
      * Bump github.com/cpuguy83/go-md2man/v2 from 2.0.5 to 2.0.6
      * update san and sanregex configuration for readability
      * reduce duplication when creating policy content
      * tweak output of build policy info
      * Name conditionals in PR finder
      * Support pr view for intra-org forks
      * Return err instead of silentError in merge queue check
      * linting pointed out this var is no longer used
      * Removed fun, but inaccessible ASCII header
      * further tweaks to the long description
      * Exit on pr merge with `-d` and merge queue
      * Addressed PR review feedback; expanded Long command help string, used ghrepo, clarified some
    abbreviations
      * Update pkg/cmd/attestation/inspect/inspect.go
      * Update gh auth commands to point to GitHub Docs
      * Reformat ext install long
      * Mention Windows quirk in ext install help text
      * Fix error mishandling in local ext install
      * Assert on err msg directly in ext install tests
      * Clarify hosts in ext install help text
      * Bump golang.org/x/crypto from 0.29.0 to 0.31.0
      * Removed now redundant file
      * minor tweak to language
      * go mod tidy
      * Deleted no-longer-used code.
      * deleted now-invalid tests, added a tiny patina of new testing.
      * Tightened up docs, deleted dead code, improved printing
      * fix file name creation on windows
      * wording
      * hard code expected digest
      * fix download test
      * use bash shell with integration tests
      * simplify var creation
      * update integration test scripts
      * fix: list branches in square brackets in gh codespace
      * try nesting scripts
      * run all tests in a single script
      * windows for loop syntax
      * use replaceAll
      * update expected file path on windows
      * run integration tests with windows specific syntax
      * run all attestation cmd integration tests automatically
      * Bump actions/attest-build-provenance from 1.4.4 to 2.1.0
      * Improve error handling in apt setup script
      * use different file name for attestation files on windows
      * test(gh run): assert branch names are enclosed in square brackets
      * docs: enhance help text and prompt for rename command
      * Revert 'Confirm auto-detected base branch'
      * Confirm auto-detected base branch
      * Merge changes from #10004
      * Set gh-merge-base from `issue develop`
      * Open PR against gh-merge-base
      * Refactor extension executable error handling
      * fix: list branches in square brackets in gh run view (#10038)
      * docs: update description of command
      * style: reformat files
      * docs: update sentence case
      * use github owned oci image
      * docs: add mention of scopes help topic in `auth refresh` command help
      * docs: add mention of scopes help topic in `auth login` command help
      * docs: add help topic for auth scopes
      * docs: improve help for browse command
      * docs: improve docs for browse command as of #5352
      * fix package reference
      * add gh attestation verify integration test for oci bundles
      * add integration test for bundle-from-oci option
      * update tests
      * update tests
      * move content of veriy policy options function into enforcement criteria
      * comment
      * try switch statement
      * remove duplicate err checking
      * get bundle issuer in another func
      * more logic updating to remove nesting
      * inverse logic for less nesting
      * remove unneeded nesting
      * wip, linting, getting tests to pass
      * wording
      * var naming
      * drop table view
      * order policy info so relevant info is printed next to each other
      * Update pkg/cmd/attestation/verification/policy.go
      * Update pkg/cmd/attestation/verification/policy.go
      * Update pkg/cmd/attestation/verification/policy.go
      * wip: added new printSummaryInspection
      * Improve error handling for missing executable
      * experiment with table output
      * Assert stderr is empty in manager_test.go
      * Update error message wording
      * Change: exit zero, still print warning to stderr
      * wording
      * Improve docs on installing extensions
      * Update language for missing extension executable
      * Update test comments about Windows behavior
      * wording
      * wording
      * wording
      * add newlines for additional policy info
      * Document requirements for local extensions
      * Warn when installing local ext with no executable
      * wording
      * formatting
      * print policy information before verifying
      * add initial policy info method
      * more wip poking around, now with table printing
      * wip, gh at inspect will check the signature on the bundle
      * wip: inspect now prints various bundle fields in a nice json

    - Update to version 2.63.2:

      * include alg with digest when fetching bundles from OCI
      * Error for mutually exclusive json and watch flags
      * Use safepaths for run download
      * Use consistent slice ordering in run download tests
      * Consolidate logic for isolating artifacts
      * Fix PR checkout panic when base repo is not in remotes
      * When renaming an existing remote in `gh repo fork`, log the change
      * Improve DNF version clarity in install steps
      * Fix formatting in client_test.go comments for linter
      * Expand logic and tests to handle edge cases
      * Refactor download testing, simpler file descends
      * Bump github.com/gabriel-vasile/mimetype from 1.4.6 to 1.4.7
      * Improve test names so there is no repetition
      * Second attempt to address exploit

    - Update to version 2.63.0:

      * Add checkout test that uses ssh git remote url
      * Rename backwards compatible credentials pattern
      * Fix CredentialPattern doc typos
      * Remove TODOs
      * Fix typos and add tests for CredentialPatternFrom* functions
      * Add SSH remote todo
      * General cleanup and docs
      * Allow repo sync fetch to use insecure credentials pattern
      * Allow client fetch to use insecure credentials pattern
      * Allow client push to use insecure credential pattern
      * Allow client pull to use insecure credential pattern
      * Allow opt-in to insecure pattern
      * Support secure credential pattern
      * Refactor error handling for missing 'workflow' scope in createRelease
      * ScopesResponder wraps StatusScopesResponder
      * Refactor `workflow` scope checking
      * pr feedback
      * pr feedback
      * Update pkg/cmd/attestation/verify/attestation_integration_test.go
      * Apply suggestions from code review
      * Refactor command documentation to use heredoc
      * pr feedback
      * remove unused test file
      * undo change
      * add more testing testing fixtures
      * update test with new test bundle
      * naming
      * update test
      * update test
      * Fix README.md code block formatting
      * clean up
      * wrap sigstore and cert ext verification into a single function
      * Adding option to return `baseRefOid` in `pr view`
      * verify cert extensions function should return filtered result list
      * pr feedback
      * Update pkg/cmd/attestation/download/download.go
      * fix function param calls
      * Update pkg/cmd/attestation/verification/extensions.go
      * Formatting fix
      * Updated formatting to be more clear
      * Updated markdown syntax for a `note`.
      * Added a section on manual verification of the relases.
      * Handle missing 'workflow' scope in createRelease
      * Modify push prompt on repo create when bare
      * Doc push behaviour for bare repo create
      * Push --mirror on bare repo create
      * Add acceptance test for bare repo create
      * Doc isLocalRepo and git.Client IsLocalRepo differences
      * Use errWithExitCode interface in repo create isLocalRepo
      * Backfill repo creation failure tests
      * Support bare repo creation
      * use logger println method
      * simplify verifyCertExtensions
      * rename type
      * refactor fetch attestations funcs

    - Update to version 2.62.0
      * CVE-2024-52308: remote code execution (RCE) when users connect
        to a malicious Codespace SSH server and use the gh codespace
        ssh or gh codespace logs commands
        (boo#1233387, GHSA-p2h2-3vg9-4p87)
      * Check extension for latest version when executed
      * Shorten extension release checking from 3s to 1s

    - includes changes from 2.61.0:
      * Enhance gh repo edit command to inform users about
        consequences of changing visibility and ensure users are
        intentional before making irreversible changes

    - Update to version 2.60.1:

      * Note token redaction in Acceptance test README
      * Refactor gpg-key delete to align with ssh-key delete
      * Add acceptance tests for org command
      * Adjust environment help for host and tokens (#9809)
      * Add SSH Key Acceptance test
      * Add Acceptance test for label command
      * Add acceptance test for gpg-key
      * Update go-internal to redact more token types in Acceptance tests
      * Address PR feedback
      * Clarify `gh` is available for GitHub Enterprise Cloud
      * Remove comment from gh auth logout
      * Add acceptance tests for auth-setup-git and formattedStringToEnv helper func
      * Use forked testscript for token redaction
      * Use new GitHub preview terms in working-with-us.md
      * Use new GitHub previews terminology in attestation
      * Test json flags for repo view and list
      * Clean up auth-login-logout acceptance test with native functionality
      * Add --token flag to `gh auth login` to accept a PAT as a flag
      * Setup acceptance testing for auth and tests for auth-token and auth-status
      * Update variable testscripts based on secret
      * Check extOwner for no value instead
      * Fix tests for invalid extension name
      * Refactor to remove code duplication
      * Linting: now that mockDataGenerator has an embedded mock, we ought to have pointer receivers in its
    funcs.
      * Minor tweaks, added backoff to getTrustDomain
      * added test for verifying we do 3 retries when fetching attestations.
      * Fix single quote not expanding vars
      * Added constant backoff retry to getAttestations.
      * Address @williammartin PR feedback
      * wip: added test that fails in the absence of a backoff.
      * add validation for local ext install
      * feat: add ArchivedAt field to Repository struct
      * Refactor `gh secret` testscript
      * Wrap true in '' in repo-fork-sync
      * Rename acceptance test directory from repos to repo
      * Remove unnecessary flags from repo-delete testscript
      * Replace LICENSE Makefile README.md acceptance api bin build cmd context docs git go.mod go.sum
    internal pkg script share test utils commands with
      * Wrap boolean strings in '' so it is clear they are strings
      * Remove unnecessary gh auth setup-git steps
      * Cleanup some inconsistencies and improve collapse some functionality
      * Add acceptance tests for repo deploy-key add/list/delete
      * Add acceptance tests for repo-fork and repo-sync
      * Add acceptance test for repo-set-default
      * Add acceptance test for repo-edit
      * Add acceptance tests for repo-list and repo-rename
      * Acceptance testing for repo-archive and repo-unarchive
      * Add acceptance test for repo-clone
      * Added acceptance test for repo-delete
      * Added test function for repos and repo-create test
      * Implement acceptance tests for search commands
      * Remove . from test case for TestTitleSurvey
      * Clean up Title Survey empty title message code
      * Add missing test to trigger acceptance tests
      * Add acceptance tests for `gh variable`
      * Minor polish / consistency
      * Fix typo in custom command doc
      * Refactor env2upper, env2lower; add docs
      * Update secret note about potential failure
      * Add testscripts for `gh secret`, helper cmds
      * Remove stdout assertion from release
      * Rename test files
      * Add acceptance tests for `release` commands
      * Implement basic API acceptance test
      * Remove unnecesary mkdir from download Acceptance test
      * Remove empty stdout checks
      * Adjust sleeps to echos in Acceptance workflows
      * Use regex assert for enable disable workflow Acceptance test
      * Watch for run to end for cancel Acceptance test
      * Include startedAt, completedAt in run steps data
      * Rewrite a sentence in CONTRIBUTING.md
      * Add filtered content output to docs
      * sleep 10s before checking for workflow run
      * Update run-rerun.txtar
      * Create cache-list-delete.txtar
      * Create run-view.txtar
      * Create run-rerun.txtar
      * Create run-download.txtar
      * Create run-delete.txtar
      * Remove IsTenancy and relevant tests from gists as they are unsupported
      * Remove unnecessary code branches
      * Add ghe.com to tests describing ghec data residency
      * Remove comment
      * auth: Removed redundant ghauth.IsTenancy(host) check
      * Use go-gh/auth package for IsEnterprise, IsTenancy, and NormalizeHostname
      * Upgrade go-gh version to 2.11.0
      * Add test coverage to places where IsEnterprise incorrectly covers Tenancy
      * Fix issue creation with metadata regex
      * Create run-cancel.txtar
      * Create workflow-run.txtar
      * Create workflow-view.txtar
      * implement workflow enable/disable acceptance test
      * implement base workflow list acceptance test
      * Add comment to acceptance make target
      * Resolve PR feedback
      * Acceptance test issue command
      * Support GH_ACCEPTANCE_SCRIPT
      * Ensure Acceptance defer failures are debuggable
      * Add acceptance task to makefile
      * build(deps): bump github.com/gabriel-vasile/mimetype from 1.4.5 to 1.4.6
      * Ensure pr create with metadata has assignment
      * Document sharedCmds func in acceptance tests
      * Correct testscript description in Acceptance readme
      * Add link to testscript pkg documentation
      * Add VSCode extension links to Acceptance README
      * Fix GH_HOST / GH_ACCEPTANCE_HOST misuse
      * Acceptance test PR list
      * Support skipping Acceptance test cleanup
      * Acceptance test PR creation with metadata
      * Suggest using legacy PAT for acceptance tests
      * Add host recommendation to Acceptance test docs
      * Don't append remaining text if more matches
      * Highlight matches in table and content
      * Split all newlines, and output no-color to non-TTY
      * Print filtered gists similar to code search
      * Show progress when filtering
      * Simplify description
      * Disallow use of --include-content without --filter
      * Improve help docs
      * Refactor filtering into existing `gist list`
      * Improve performance
      * Add `gist search` command
      * Fix api tests after function signature changes
      * Return nil instead of empty objects when err
      * Fix license list and view tests
      * Validate required env vars not-empty for Acceptance tests
      * Add go to test instructions in Acceptance README
      * Apply suggestions from code review
      * Error if acceptance tests are targeting github or cli orgs
      * Add codecoverage to Acceptance README
      * Isolate acceptance env vars
      * Add Writing Tests section to Acceptance README
      * Add Debug and Authoring sections to Acceptance README
      * Acceptance test PR comment
      * Acceptance test PR merge and rebase
      * Note syntax highlighting support for txtar files
      * Refactor acceptance test environment handling
      * Add initial acceptance test README
      * Use txtar extension for testscripts
      * Support targeting other hosts in acceptance tests
      * Use stdout2env in PR acceptance tests
      * Acceptance test PR checkout
      * Add pr view test script
      * Initial testscript introduction
      * While we're at it, let's ensure VerifyCertExtensions can't be tricked the same way.
      * Add examples for creating `.gitignore` files
      * Update help for license view
      * Refactor http error handling
      * implement `--web` flag for license view
      * Fix license view help doc, add LICENSE.md example
      * Update help and fix heredoc indentation
      * Add SPDX ID to license list output
      * Fix ExactArgs invocation
      * Add `Long` for license list indicating limitations
      * Update function names
      * Reverse repo/shared package name change
      * If provided with zero attestations to verify, the LiveSigstoreVerifier.Verify func should return an
    error.
      * Bump cli/oauth to 1.1.1
      * Add test coverage for TitleSurvey change
      * Fix failing test for pr and issue create
      * Make the X in the error message red and print with io writer
      * Handle errors from parsing hostname in auth flow
      * Apply suggestions from code review
      * Refactor tests and add new tests
      * Move API calls to queries_repo.go
      * Allow user to override markdown wrap width via $GH_MDWIDTH from environment
      * Add handling of empty titles for Issues and PRs
      * Print the login URL even when opening a browser
      * Apply suggestions from code review
      * Update SECURITY.md
      * Fix typo and wordsmithing
      * fix typo
      * Remove trailing space from heading
      * Revise wording
      * Update docs to allow community submitted designs
      * Implement license view
      * Implement gitignore view
      * implement gitignore list
      * Update license table headings and tests
      * Fix ListLicenseTemplates doc
      * fix output capitalization
      * Cleanup rendering and tests
      * Remove json output option
      * Divide shared repo package and add queries tests
      * First pass at implementing `gh repo license list`
      * Emit a log message when extension installation falls back to a darwin-amd64 binary on an Apple Silicon
    macOS machine

    - Update to version 2.58.0:
      * build(deps): bump github.com/theupdateframework/go-tuf/v2
      * Include `dnf5` commands
      * Add GPG key instructions to appropriate sections
      * Update docs language to remove possible confusion around 'where you log in'
      * Change conditional in promptForHostname to better reflect prompter changes
      * Shorten language on Authenticate with a GitHub host.
      * Update language on docstring for `gh auth login`
      * Change prompts for `gh auth login` to reflect change from GHE to Other
      * Sentence case 'Other' option in hostname prompt
      * build(deps): bump github.com/henvic/httpretty from 0.1.3 to 0.1.4
      * Add documentation explaining how to use `hostname` for `gh auth login`
      * Replace 'GitHub Enterprise Server' with 'other' in `gh auth login` prompt
      * fix tenant-awareness for trusted-root command
      * Fix test
      * Update pkg/cmd/extension/manager.go
      * Update comment formatting
      * Use new HasActiveToken method in trustedroot.go
      * Add HasActiveToken method to AuthConfig interface
      * Add HasActiveToken to AuthConfig.
      * Improve error presentation
      * Improve the suggested command for creating an issue when an extension doesn't have a binary for your
    platform
      * Update pkg/cmd/attestation/trustedroot/trustedroot_test.go
      * build(deps): bump github.com/cpuguy83/go-md2man/v2 from 2.0.4 to 2.0.5
      * enforce auth for tenancy
      * disable auth check for att trusted-root cmd
      * better error for att verify custom issuer mismatch
      * Enhance gh repo create docs, fix random cmd link

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233387");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HUMKXZZVR2XTEF5OINR7OTNWNR5IVCYQ/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07dfb8e7");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-52308");
  script_set_attribute(attribute:"solution", value:
"Update the affected gh, gh-bash-completion, gh-fish-completion and / or gh-zsh-completion packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52308");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gh-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gh-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gh-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'gh-2.65.0-bp156.2.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gh-bash-completion-2.65.0-bp156.2.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gh-fish-completion-2.65.0-bp156.2.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gh-zsh-completion-2.65.0-bp156.2.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gh / gh-bash-completion / gh-fish-completion / gh-zsh-completion');
}
