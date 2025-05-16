#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0091-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(232825);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/16");

  script_cve_id("CVE-2025-22868");

  script_name(english:"openSUSE 15 Security Update : restic (openSUSE-SU-2025:0091-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2025:0091-1 advisory.

    - Fixed CVE-2025-22868: golang.org/x/oauth2/jws: Unexpected memory consumption during token parsing in
    golang.org/x/oauth2  (boo#1239264)

    - Update to version 0.17.3

      - Fix #4971: Fix unusable mount on macOS Sonoma
      - Fix #5003: Fix metadata errors during backup of removable disks
        on Windows
      - Fix #5101: Do not retry load/list operation if SFTP connection
        is broken
      - Fix #5107: Fix metadata error on Windows for backups using VSS
      - Enh #5096: Allow prune --dry-run without lock

    - Update to version 0.17.2

      - Fix #4004: Support container-level SAS/SAT tokens for Azure
        backend
      - Fix #5047: Resolve potential error during concurrent cache
        cleanup
      - Fix #5050: Return error if tag fails to lock repository
      - Fix #5057: Exclude irregular files from backups
      - Fix #5063: Correctly backup extended metadata when using VSS on
        Windows

    - Update to version 0.17.1

      - Fix #2004: Correctly handle volume names in backup command on
        Windows
      - Fix #4945: Include missing backup error text with --json
      - Fix #4953: Correctly handle long paths on older Windows
        versions
      - Fix #4957: Fix delayed cancellation of certain commands
      - Fix #4958: Don't ignore metadata-setting errors during restore
      - Fix #4969: Correctly restore timestamp for files with resource
        forks on macOS
      - Fix #4975: Prevent backup --stdin-from-command from panicking
      - Fix #4980: Skip extended attribute processing on unsupported
        Windows volumes
      - Fix #5004: Fix spurious 'A Required Privilege Is Not Held by
        the Client' error
      - Fix #5005: Fix rare failures to retry locking a repository
      - Fix #5018: Improve HTTP/2 support for REST backend
      - Chg #4953: Also back up files with incomplete metadata
      - Enh #4795: Display progress bar for restore --verify
      - Enh #4934: Automatically clear removed snapshots from cache
      - Enh #4944: Print JSON-formatted errors during restore --json
      - Enh #4959: Return exit code 12 for 'bad password' errors
      - Enh #4970: Make timeout for stuck requests customizable

    - Update to version 0.17.0

      - Fix #3600: Handle unreadable xattrs in folders above backup
        source
      - Fix #4209: Fix slow SFTP upload performance
      - Fix #4503: Correct hardlink handling in stats command
      - Fix #4568: Prevent forget --keep-tags <invalid> from deleting
        all snapshots
      - Fix #4615: Make find not sometimes ignore directories
      - Fix #4656: Properly report ID of newly added keys
      - Fix #4703: Shutdown cleanly when receiving SIGTERM
      - Fix #4709: Correct --no-lock handling of ls and tag commands
      - Fix #4760: Fix possible error on concurrent cache cleanup
      - Fix #4850: Handle UTF-16 password files in key command
        correctly
      - Fix #4902: Update snapshot summary on rewrite
      - Chg #956: Return exit code 10 and 11 for non-existing and
        locked repository
      - Chg #4540: Require at least ARMv6 for ARM binaries
      - Chg #4602: Deprecate legacy index format and s3legacy
        repository layout
      - Chg #4627: Redesign backend error handling to improve
        reliability
      - Chg #4707: Disable S3 anonymous authentication by default
      - Chg #4744: Include full key ID in JSON output of key list
      - Enh #662: Optionally skip snapshot creation if nothing changed
      - Enh #693: Include snapshot size in snapshots output
      - Enh #805: Add bitrot detection to diff command
      - Enh #828: Improve features of the repair packs command
      - Enh #1786: Support repositories with empty password
      - Enh #2348: Add --delete option to restore command
      - Enh #3067: Add extended options to configure Windows Shadow
        Copy Service
      - Enh #3406: Improve dump performance for large files
      - Enh #3806: Optimize and make prune command resumable
      - Enh #4006: (alpha) Store deviceID only for hardlinks
      - Enh #4048: Add support for FUSE-T with mount on macOS
      - Enh #4251: Support reading backup from a command's standard
        output
      - Enh #4287: Support connection to rest-server using unix socket
      - Enh #4354: Significantly reduce prune memory usage
      - Enh #4437: Make check command create non-existent cache
        directory
      - Enh #4472: Support AWS Assume Role for S3 backend
      - Enh #4547: Add --json option to version command
      - Enh #4549: Add --ncdu option to ls command
      - Enh #4573: Support rewriting host and time metadata in
        snapshots
      - Enh #4583: Ignore s3.storage-class archive tiers for metadata
      - Enh #4590: Speed up mount command's error detection
      - Enh #4601: Add support for feature flags
      - Enh #4611: Back up more file metadata on Windows
      - Enh #4664: Make ls use message_type field in JSON output
      - Enh #4676: Make key command's actions separate sub-commands
      - Enh #4678: Add --target option to the dump command
      - Enh #4708: Back up and restore SecurityDescriptors on Windows
      - Enh #4733: Allow specifying --host via environment variable
      - Enh #4737: Include snapshot ID in reason field of forget JSON
        output
      - Enh #4764: Support forgetting all snapshots
      - Enh #4768: Allow specifying custom User-Agent for outgoing
        requests
      - Enh #4781: Add restore options to read include/exclude patterns
        from files
      - Enh #4807: Support Extended Attributes on Windows NTFS
      - Enh #4817: Make overwrite behavior of restore customizable
      - Enh #4839: Add dry-run support to restore command
      for all the details see https://github.com/restic/restic/releases/tag/v0.17.0
      or /usr/share/doc/packages/restic/CHANGELOG.md

    - Update to version 0.16.5
      - Enh #4799: Add option to force use of Azure CLI credential
      - Enh #4873: Update dependencies

    - Update to version 0.16.4
      This release works around and improves detection of a bug in the
      compression library used by restic. The resulting issue only
      happens when using restic 0.16.3 and the max compression level
      (the default auto and off compression levels are not affected),
      and when the source files being backed up have specific data in
      them to trigger the bug. If you use max compression, you can use
      restic check --read-data to make sure you're not affected.

    - Update to version 0.16.3

      - Fix #4560: Improve errors for irregular files on Windows
      - Fix #4574: Support backup of deduplicated files on Windows
        again
      - Fix #4612: Improve error handling for rclone backend
      - Fix #4624: Correct restore progress information if an error
        occurs
      - Fix #4626: Improve reliability of restoring large files

    - Update to version 0.16.2

      - Fix #4540: Restore ARMv5 support for ARM binaries
      - Fix #4545: Repair documentation build on Read the Docs

    - Update to version 0.16.1

      A very long list of improvements for all the details see
      https://github.com/restic/restic/releases/tag/v0.16.1
      It contains an important bug fix which prevents data corruption
      when compression is set to max.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239264");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3WXUOMZG43G5AZBMH5HY5IUTZ2CLZL6M/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f01e9a5e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22868");
  script_set_attribute(attribute:"solution", value:
"Update the affected restic, restic-bash-completion and / or restic-zsh-completion packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22868");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/16");

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
    {'reference':'restic-0.17.3-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'restic-bash-completion-0.17.3-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'restic-zsh-completion-0.17.3-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'restic / restic-bash-completion / restic-zsh-completion');
}
