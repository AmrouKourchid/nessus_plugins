#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0276-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(206444);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/04");

  script_cve_id(
    "CVE-2024-25641",
    "CVE-2024-27082",
    "CVE-2024-29894",
    "CVE-2024-31443",
    "CVE-2024-31444",
    "CVE-2024-31445",
    "CVE-2024-31458",
    "CVE-2024-31459",
    "CVE-2024-31460",
    "CVE-2024-34340"
  );

  script_name(english:"openSUSE 15 Security Update : cacti, cacti-spine (openSUSE-SU-2024:0276-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0276-1 advisory.

    - cacti 1.2.27:
      * CVE-2024-34340: Authentication Bypass when using using older password hashes (boo#1224240)
      * CVE-2024-25641: RCE vulnerability when importing packages (boo#1224229)
      * CVE-2024-31459: RCE vulnerability when plugins include files (boo#1224238)
      * CVE-2024-31460: SQL Injection vulnerability when using tree rules through Automation API (boo#1224239)
      * CVE-2024-29894: XSS vulnerability when using JavaScript based messaging API (boo#1224231)
      * CVE-2024-31458: SQL Injection vulnerability when using form templates (boo#1224241)
      * CVE-2024-31444: XSS vulnerability when reading tree rules with Automation API (boo#1224236)
      * CVE-2024-31443: XSS vulnerability when managing data queries (boo#1224235)
      * CVE-2024-31445: SQL Injection vulnerability when retrieving graphs using Automation API (boo#1224237)
      * CVE-2024-27082: XSS vulnerability when managing trees (boo#1224230)
      * Improve PHP 8.3 support
      * When importing packages via command line, data source profile could not be selected
      * When changing password, returning to previous page does not always work
      * When using LDAP authentication the first time, warnings may appear in logs
      * When editing/viewing devices, add IPv6 info to hostname tooltip
      * Improve speed of polling when Boost is enabled
      * Improve support for Half-Hour time zones
      * When user session not found, device lists can be incorrectly returned
      * On import, legacy templates may generate warnings
      * Improve support for alternate locations of Ping
      * Improve PHP 8.1 support for Installer
      * Fix issues with number formatting
      * Improve PHP 8.1 support when SpikeKill is run first time
      * Improve PHP 8.1 support for SpikeKill
      * When using Chinese to search for graphics, garbled characters appear.
      * When importing templates, preview mode will not always load
      * When remote poller is installed, MySQL TimeZone DB checks are not performed
      * When Remote Poller installation completes, no finish button is shown
      * Unauthorized agents should be recorded into logs
      * Poller cache may not always update if hostname changes
      * When using CMD poller, Failure and Recovery dates may have incorrect values
      * Saving a Tree can cause the tree to become unpublished
      * Web Basic Authentication does not record user logins
      * When using Accent-based languages, translations may not work properly
      * Fix automation expressions for device rules
      * Improve PHP 8.1 Support during fresh install with boost
      * Add a device 'enabled/disabled' indicator next to the graphs
      * Notify the admin periodically when a remote data collector goes into heartbeat status
      * Add template for Aruba Clearpass
      * Add fliter/sort of Device Templates by Graph Templates

    - cacti-spine 1.2.27:
      * Restore AES Support

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224241");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JAAOBG657QTBRHKB55GHL2C7553NKG67/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?762e8663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-29894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-31443");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-31444");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-31445");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-31458");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-31459");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-31460");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-34340");
  script_set_attribute(attribute:"solution", value:
"Update the affected cacti and / or cacti-spine packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34340");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cacti Import Packages RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
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
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'cacti-1.2.27-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cacti-spine-1.2.27-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cacti / cacti-spine');
}
