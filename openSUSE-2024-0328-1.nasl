#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0328-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(208677);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/10");

  script_cve_id("CVE-2024-42008", "CVE-2024-42009", "CVE-2024-42010");

  script_name(english:"openSUSE 15 Security Update : roundcubemail (openSUSE-SU-2024:0328-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0328-1 advisory.

    Update to 1.6.8
    This is a security update to the stable version 1.6 of Roundcube Webmail.
    It provides fixes to recently reported security vulnerabilities:

      * Fix XSS vulnerability in post-processing of sanitized HTML content [CVE-2024-42009]
      * Fix XSS vulnerability in serving of attachments other than HTML or SVG [CVE-2024-42008]
      * Fix information leak (access to remote content) via insufficient CSS filtering [CVE-2024-42010]

      CHANGELOG

      * Managesieve: Protect special scripts in managesieve_kolab_master mode
      * Fix newmail_notifier notification focus in Chrome (#9467)
      * Fix fatal error when parsing some TNEF attachments (#9462)
      * Fix double scrollbar when composing a mail with many plain text lines (#7760)
      * Fix decoding mail parts with multiple base64-encoded text blocks (#9290)
      * Fix bug where some messages could get malformed in an import from a MBOX file (#9510)
      * Fix invalid line break characters in multi-line text in Sieve scripts (#9543)
      * Fix bug where 'with attachment' filter could fail on some fts engines (#9514)
      * Fix bug where an unhandled exception was caused by an invalid image attachment (#9475)
      * Fix bug where a long subject title could not be displayed in some cases (#9416)
      * Fix infinite loop when parsing malformed Sieve script (#9562)
      * Fix bug where imap_conn_option's 'socket' was ignored (#9566)
      * Fix XSS vulnerability in post-processing of sanitized HTML content [CVE-2024-42009]
      * Fix XSS vulnerability in serving of attachments other than HTML or SVG [CVE-2024-42008]
      * Fix information leak (access to remote content) via insufficient CSS filtering [CVE-2024-42010]

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228901");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Q5GOCYS6W7WGAIH6NILISNVXQC4O7Z53/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11db3880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42010");
  script_set_attribute(attribute:"solution", value:
"Update the affected roundcubemail package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42009");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
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
if (os_release !~ "^(SUSE15\.5|SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5 / 15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'roundcubemail-1.6.8-bp156.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'roundcubemail-1.6.8-bp156.2.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'roundcubemail');
}
