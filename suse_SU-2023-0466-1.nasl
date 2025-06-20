#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:0466-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(171767);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/14");

  script_cve_id(
    "CVE-2023-0767",
    "CVE-2023-25728",
    "CVE-2023-25729",
    "CVE-2023-25730",
    "CVE-2023-25732",
    "CVE-2023-25734",
    "CVE-2023-25735",
    "CVE-2023-25737",
    "CVE-2023-25738",
    "CVE-2023-25739",
    "CVE-2023-25742",
    "CVE-2023-25743",
    "CVE-2023-25744",
    "CVE-2023-25746"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:0466-1");

  script_name(english:"SUSE SLES12 Security Update : MozillaFirefox (SUSE-SU-2023:0466-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:0466-1 advisory.

  - An attacker could construct a PKCS 12 cert bundle in such a way that could allow for arbitrary memory
    writes via PKCS 12 Safe Bag attributes being mishandled. This vulnerability affects Firefox < 110,
    Thunderbird < 102.8, and Firefox ESR < 102.8. (CVE-2023-0767)

  - The <code>Content-Security-Policy-Report-Only</code> header could allow an attacker to leak a child
    iframe's unredacted URI when interaction with that iframe triggers a redirect. This vulnerability affects
    Firefox < 110, Thunderbird < 102.8, and Firefox ESR < 102.8. (CVE-2023-25728)

  - Permission prompts for opening external schemes were only shown for <code>ContentPrincipals</code>
    resulting in extensions being able to open them without user interaction via
    <code>ExpandedPrincipals</code>. This could lead to further malicious actions such as downloading files or
    interacting with software already installed on the system. This vulnerability affects Firefox < 110,
    Thunderbird < 102.8, and Firefox ESR < 102.8. (CVE-2023-25729)

  - A background script invoking <code>requestFullscreen</code> and then blocking the main thread could force
    the browser into fullscreen mode indefinitely, resulting in potential user confusion or spoofing attacks.
    This vulnerability affects Firefox < 110, Thunderbird < 102.8, and Firefox ESR < 102.8. (CVE-2023-25730)

  - When encoding data from an <code>inputStream</code> in <code>xpcom</code> the size of the input being
    encoded was not correctly calculated potentially leading to an out of bounds memory write. This
    vulnerability affects Firefox < 110, Thunderbird < 102.8, and Firefox ESR < 102.8. (CVE-2023-25732)

  - After downloading a Windows <code>.url</code> shortcut from the local filesystem, an attacker could supply
    a remote path that would lead to unexpected network requests from the operating system. This also had the
    potential to leak NTLM credentials to the resource.<br>*This bug only affects Firefox on Windows. Other
    operating systems are unaffected.*. This vulnerability affects Firefox < 110, Thunderbird < 102.8, and
    Firefox ESR < 102.8. (CVE-2023-25734)

  - Cross-compartment wrappers wrapping a scripted proxy could have caused objects from other compartments to
    be stored in the main compartment resulting in a use-after-free after unwrapping the proxy. This
    vulnerability affects Firefox < 110, Thunderbird < 102.8, and Firefox ESR < 102.8. (CVE-2023-25735)

  - An invalid downcast from <code>nsTextNode</code> to <code>SVGElement</code> could have lead to undefined
    behavior. This vulnerability affects Firefox < 110, Thunderbird < 102.8, and Firefox ESR < 102.8.
    (CVE-2023-25737)

  - Members of the <code>DEVMODEW</code> struct set by the printer device driver weren't being validated and
    could have resulted in invalid values which in turn would cause the browser to attempt out of bounds
    access to related variables.<br>*This bug only affects Firefox on Windows. Other operating systems are
    unaffected.*. This vulnerability affects Firefox < 110, Thunderbird < 102.8, and Firefox ESR < 102.8.
    (CVE-2023-25738)

  - Module load requests that failed were not being checked as to whether or not they were cancelled causing a
    use-after-free in <code>ScriptLoadContext</code>. This vulnerability affects Firefox < 110, Thunderbird <
    102.8, and Firefox ESR < 102.8. (CVE-2023-25739)

  - When importing a SPKI RSA public key as ECDSA P-256, the key would be handled incorrectly causing the tab
    to crash. This vulnerability affects Firefox < 110, Thunderbird < 102.8, and Firefox ESR < 102.8.
    (CVE-2023-25742)

  - A lack of in app notification for entering fullscreen mode could have lead to a malicious website spoofing
    browser chrome.<br>*This bug only affects Firefox Focus. Other versions of Firefox are unaffected.*. This
    vulnerability affects Firefox < 110 and Firefox ESR < 102.8. (CVE-2023-25743)

  - Mozilla developers Kershaw Chang and the Mozilla Fuzzing Team reported memory safety bugs present in
    Firefox 109 and Firefox ESR 102.7. Some of these bugs showed evidence of memory corruption and we presume
    that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability
    affects Firefox < 110 and Firefox ESR < 102.8. (CVE-2023-25744)

  - Mozilla developers Philipp and Gabriele Svelto reported memory safety bugs present in Firefox ESR 102.7.
    Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of
    these could have been exploited to run arbitrary code. This vulnerability affects Thunderbird < 102.8 and
    Firefox ESR < 102.8. (CVE-2023-25746)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208144");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0767");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25728");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25738");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25746");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-February/013853.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bbc11d5");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-devel and / or MozillaFirefox-translations-common packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25746");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2/4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaFirefox-102.8.0-112.150.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'MozillaFirefox-devel-102.8.0-112.150.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'MozillaFirefox-translations-common-102.8.0-112.150.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'MozillaFirefox-102.8.0-112.150.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'MozillaFirefox-devel-102.8.0-112.150.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'MozillaFirefox-translations-common-102.8.0-112.150.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'MozillaFirefox-devel-102.8.0-112.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'MozillaFirefox-102.8.0-112.150.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'MozillaFirefox-devel-102.8.0-112.150.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'MozillaFirefox-translations-common-102.8.0-112.150.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'MozillaFirefox-102.8.0-112.150.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'MozillaFirefox-devel-102.8.0-112.150.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'MozillaFirefox-translations-common-102.8.0-112.150.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'MozillaFirefox-102.8.0-112.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'MozillaFirefox-translations-common-102.8.0-112.150.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'MozillaFirefox-102.8.0-112.150.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'MozillaFirefox-102.8.0-112.150.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'MozillaFirefox-devel-102.8.0-112.150.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'MozillaFirefox-devel-102.8.0-112.150.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'MozillaFirefox-translations-common-102.8.0-112.150.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'MozillaFirefox-translations-common-102.8.0-112.150.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-devel / etc');
}
