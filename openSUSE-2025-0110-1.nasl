#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0110-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(233641);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_name(english:"openSUSE 15 Security Update : restic (openSUSE-SU-2025:0110-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2025:0110-1 advisory.

    Update to 0.18.0

    - Sec #5291: Mitigate attack on content-defined chunking algorithm
    - Fix #1843: Correctly restore long filepaths' timestamp on old Windows
    - Fix #2165: Ignore disappeared backup source files
    - Fix #5153: Include root tree when searching using find --tree
    - Fix #5169: Prevent Windows VSS event log 8194 warnings for backup with fs snapshot
    - Fix #5212: Fix duplicate data handling in prune --max-unused
    - Fix #5249: Fix creation of oversized index by repair index --read-all-packs
    - Fix #5259: Fix rare crash in command output
    - Chg #4938: Update dependencies and require Go 1.23 or newer
    - Chg #5162: Promote feature flags
    - Enh #1378: Add JSON support to check command
    - Enh #2511: Support generating shell completions to stdout
    - Enh #3697: Allow excluding online-only cloud files (e.g.  OneDrive)
    - Enh #4179: Add sort option to ls command
    - Enh #4433: Change default sort order for find output
    - Enh #4521: Add support for Microsoft Blob Storage access tiers
    - Enh #4942: Add snapshot summary statistics to rewritten snapshots
    - Enh #4948: Format exit errors as JSON when requested
    - Enh #4983: Add SLSA provenance to GHCR container images
    - Enh #5054: Enable compression for ZIP archives in dump command
    - Enh #5081: Add retry mechanism for loading repository config
    - Enh #5089: Allow including/excluding extended file attributes during restore
    - Enh #5092: Show count of deleted files and directories during restore
    - Enh #5109: Make small pack size configurable for prune
    - Enh #5119: Add start and end timestamps to backup JSON output
    - Enh #5131: Add DragonFlyBSD support
    - Enh #5137: Make tag command print which snapshots were modified
    - Enh #5141: Provide clear error message if AZURE_ACCOUNT_NAME is not set
    - Enh #5173: Add experimental S3 cold storage support
    - Enh #5174: Add xattr support for NetBSD 10+
    - Enh #5251: Improve retry handling for flaky rclone backends
    - Enh #52897: Make recover automatically rebuild index when needed

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/774IYQZ7MM6B6XG4OUL4ZECAW4Q5WNZN/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5faf553");
  script_set_attribute(attribute:"solution", value:
"Update the affected restic, restic-bash-completion and / or restic-zsh-completion packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:restic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:restic-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:restic-zsh-completion");
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
    {'reference':'restic-0.18.0-bp156.2.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'restic-bash-completion-0.18.0-bp156.2.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'restic-zsh-completion-0.18.0-bp156.2.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'restic / restic-bash-completion / restic-zsh-completion');
}
