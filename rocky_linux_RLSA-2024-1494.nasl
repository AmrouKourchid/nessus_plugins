#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:1494.
##

include('compat.inc');

if (description)
{
  script_id(192611);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_cve_id(
    "CVE-2023-5388",
    "CVE-2024-0743",
    "CVE-2024-1936",
    "CVE-2024-2607",
    "CVE-2024-2608",
    "CVE-2024-2610",
    "CVE-2024-2611",
    "CVE-2024-2612",
    "CVE-2024-2614"
  );
  script_xref(name:"IAVA", value:"2024-A-0053-S");
  script_xref(name:"IAVA", value:"2024-A-0133-S");
  script_xref(name:"RLSA", value:"2024:1494");
  script_xref(name:"IAVA", value:"2024-A-0174-S");

  script_name(english:"Rocky Linux 8 : thunderbird (RLSA-2024:1494)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:1494 advisory.

  - NSS was susceptible to a timing side-channel attack when performing RSA decryption. This attack could
    potentially allow an attacker to recover the private data. This vulnerability affects Firefox < 124,
    Firefox ESR < 115.9, and Thunderbird < 115.9. (CVE-2023-5388)

  - An unchecked return value in TLS handshake code could have caused a potentially exploitable crash. This
    vulnerability affects Firefox < 122, Firefox ESR < 115.9, and Thunderbird < 115.9. (CVE-2024-0743)

  - The encrypted subject of an email message could be incorrectly and permanently assigned to an arbitrary
    other email message in Thunderbird's local cache. Consequently, when replying to the contaminated email
    message, the user might accidentally leak the confidential subject to a third party. While this update
    fixes the bug and avoids future message contamination, it does not automatically repair existing
    contaminations. Users are advised to use the repair folder functionality, which is available from the
    context menu of email folders, which will erase incorrect subject assignments. This vulnerability affects
    Thunderbird < 115.8.1. (CVE-2024-1936)

  - Return registers were overwritten which could have allowed an attacker to execute arbitrary code. *Note:*
    This issue only affected Armv7-A systems. Other operating systems are unaffected. This vulnerability
    affects Firefox < 124, Firefox ESR < 115.9, and Thunderbird < 115.9. (CVE-2024-2607)

  - `AppendEncodedAttributeValue(), ExtraSpaceNeededForAttrEncoding()` and `AppendEncodedCharacters()` could
    have experienced integer overflows, causing underallocation of an output buffer leading to an out of
    bounds write. This vulnerability affects Firefox < 124, Firefox ESR < 115.9, and Thunderbird < 115.9.
    (CVE-2024-2608)

  - Using a markup injection an attacker could have stolen nonce values. This could have been used to bypass
    strict content security policies. This vulnerability affects Firefox < 124, Firefox ESR < 115.9, and
    Thunderbird < 115.9. (CVE-2024-2610)

  - A missing delay on when pointer lock was used could have allowed a malicious page to trick a user into
    granting permissions. This vulnerability affects Firefox < 124, Firefox ESR < 115.9, and Thunderbird <
    115.9. (CVE-2024-2611)

  - If an attacker could find a way to trigger a particular code path in `SafeRefPtr`, it could have triggered
    a crash or potentially be leveraged to achieve code execution. This vulnerability affects Firefox < 124,
    Firefox ESR < 115.9, and Thunderbird < 115.9. (CVE-2024-2612)

  - Memory safety bugs present in Firefox 123, Firefox ESR 115.8, and Thunderbird 115.8. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 124, Firefox ESR < 115.9, and
    Thunderbird < 115.9. (CVE-2024-2614)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:1494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2260012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270666");
  script_set_attribute(attribute:"solution", value:
"Update the affected thunderbird, thunderbird-debuginfo and / or thunderbird-debugsource packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2614");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:thunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'thunderbird-115.9.0-1.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-115.9.0-1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-115.9.0-1.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-115.9.0-1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debugsource-115.9.0-1.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debugsource-115.9.0-1.el8_9', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird / thunderbird-debuginfo / thunderbird-debugsource');
}
