#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0227-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(204823);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/28");

  script_cve_id("CVE-2024-6104");

  script_name(english:"openSUSE 15 Security Update : gh (openSUSE-SU-2024:0227-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2024:0227-1 advisory.

    Update to version 2.53.0:

    * CVE-2024-6104: gh: hashicorp/go-retryablehttp: url might write sensitive information to log file
    (boo#1227035)

    * Disable `TestGetTrustedRoot/successfully_verifies_TUF_root` test due to
    https://github.com/cli/cli/issues/8928
    * Rename package directory and files
    * Rename package name to `update_branch`
    * Rename `gh pr update` to `gh pr update-branch`
    * Add test case for merge conflict error
    * Handle merge conflict error
    * Return error if PR is not mergeable
    * Replace literals with consts for `Mergeable` field values
    * Add separate type for `PullRequest.Mergeable` field
    * Remove unused flag
    * Print message on stdout instead of stderr
    * Raise error if editor is used in non-tty mode
    * Add tests for JSON field support on issue and pr view commands
    * docs: Update documentation for `gh repo create` to clarify owner
    * Ensure PR does not panic when stateReason is requested
    * Add `createdAt` field to tests
    * Add `createdAt` field to `Variable` type
    * Add test for exporting as JSON
    * Add test for JSON output
    * Only populate selected repo information for JSON output
    * Add test to verify JSON exporter gets set
    * Add `--json` option support
    * Use `Variable` type defined in `shared` package
    * Add tests for JSON output
    * Move `Variable` type and `PopulateSelectedRepositoryInformation` func to shared
    * Fix query parameter name
    * Update tests to account for ref comparison step
    * Improve query variable names
    * Check if PR branch is already up-to-date
    * Add `ComparePullRequestBaseBranchWith` function
    * Run `go mod tidy`
    * Add test to verify `--repo` requires non-empty selector
    * Require non-empty selector when `--repo` override is used
    * Run `go mod tidy`
    * Register `update` command
    * Add tests for `pr update` command
    * Add `pr update` command
    * Add `UpdatePullRequestBranch` method
    * Upgrade `shurcooL/githubv4`

    Update to version 2.52.0:

    * Attestation Verification - Buffer Fix
    * Remove beta note from attestation top level command
    * Removed beta note from `gh at download`.
    * Removed beta note from `gh at verify`, clarified reusable workflows use case.
    * add `-a` flag to `gh run list`

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227035");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/G2COZIDAEHXSE2NGBIJOMDBA64FCPZOP/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b3a9640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6104");
  script_set_attribute(attribute:"solution", value:
"Update the affected gh, gh-bash-completion, gh-fish-completion and / or gh-zsh-completion packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6104");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gh-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gh-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gh-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_release !~ "^(SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'gh-2.53.0-bp155.2.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gh-bash-completion-2.53.0-bp155.2.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gh-fish-completion-2.53.0-bp155.2.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gh-zsh-completion-2.53.0-bp155.2.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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
