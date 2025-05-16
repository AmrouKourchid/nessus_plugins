#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0257-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(206086);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/22");

  script_cve_id("CVE-2023-47272");

  script_name(english:"openSUSE 15 Security Update : roundcubemail (openSUSE-SU-2024:0257-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by a vulnerability as referenced in the openSUSE-
SU-2024:0257-1 advisory.

    Update to 1.6.7

    This is a security update to the stable version 1.6 of Roundcube Webmail.
    It provides a fix to a recently reported XSS vulnerabilities:

      * Fix cross-site scripting (XSS) vulnerability in handling SVG animate attributes.
        Reported by Valentin T. and Lutz Wolf of CrowdStrike.
      * Fix cross-site scripting (XSS) vulnerability in handling list columns from user preferences.
        Reported by Huy Nguyn Phm Nht.
      * Fix command injection via crafted im_convert_path/im_identify_path on Windows.
        Reported by Huy Nguyn Phm Nht.

      CHANGELOG

      * Makefile: Use phpDocumentor v3.4 for the Framework docs (#9313)
      * Fix bug where HTML entities in URLs were not decoded on HTML to plain text conversion (#9312)
      * Fix bug in collapsing/expanding folders with some special characters in names (#9324)
      * Fix PHP8 warnings (#9363, #9365, #9429)
      * Fix missing field labels in CSV import, for some locales (#9393)
      * Fix cross-site scripting (XSS) vulnerability in handling SVG animate attributes
      * Fix cross-site scripting (XSS) vulnerability in handling list columns from user preferences
      * Fix command injection via crafted im_convert_path/im_identify_path on Windows

    Update to 1.6.6:

      * Fix regression in handling LDAP search_fields configuration parameter (#9210)
      * Enigma: Fix finding of a private key when decrypting a message using GnuPG v2.3
      * Fix page jump menu flickering on click (#9196)
      * Update to TinyMCE 5.10.9 security release (#9228)
      * Fix PHP8 warnings (#9235, #9238, #9242, #9306)
      * Fix saving other encryption settings besides enigma's (#9240)
      * Fix unneeded php command use in installto.sh and deluser.sh scripts (#9237)
      * Fix TinyMCE localization installation (#9266)
      * Fix bug where trailing non-ascii characters in email addresses
        could have been removed in recipient input (#9257)
      * Fix IMAP GETMETADATA command with options - RFC5464

    Update to 1.6.5 (boo#1216895):

      * Fix cross-site scripting (XSS) vulnerability in setting
        Content-Type/Content-Disposition for attachment
        preview/download  CVE-2023-47272

      Other changes:

      * Fix PHP8 fatal error when parsing a malformed BODYSTRUCTURE (#9171)
      * Fix duplicated Inbox folder on IMAP servers that do not use Inbox
        folder with all capital letters (#9166)
      * Fix PHP warnings (#9174)
      * Fix UI issue when dealing with an invalid managesieve_default_headers
        value (#9175)
      * Fix bug where images attached to application/smil messages
        weren't displayed (#8870)
      * Fix PHP string replacement error in utils/error.php (#9185)
      * Fix regression where smtp_user did not allow pre/post strings
        before/after %u placeholder (#9162)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216895");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JQ3GTO6YI3BLAIR7PQZYZ5LRFR7OKTWN/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?adae3487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47272");
  script_set_attribute(attribute:"solution", value:
"Update the affected roundcubemail package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47272");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:roundcubemail");
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
    {'reference':'roundcubemail-1.6.7-bp155.2.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'roundcubemail');
}
