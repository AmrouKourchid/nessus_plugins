#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3603-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(208781);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/17");

  script_cve_id(
    "CVE-2024-8900",
    "CVE-2024-9392",
    "CVE-2024-9393",
    "CVE-2024-9394",
    "CVE-2024-9396",
    "CVE-2024-9397",
    "CVE-2024-9398",
    "CVE-2024-9399",
    "CVE-2024-9400",
    "CVE-2024-9401",
    "CVE-2024-9402",
    "CVE-2024-9680"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3603-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/11/05");

  script_name(english:"SUSE SLES12 Security Update : MozillaFirefox (SUSE-SU-2024:3603-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:3603-1 advisory.

    Update to Firefox Extended Support Release 128.3.1 ESR MFSA 2024-51 (bsc#1231413)

    - CVE-2024-9680: Use-after-free in Animation timeline (bmo#1923344)

    Also includes the following CVEs from MFSA 2024-47 (bsc#1230979)

    - CVE-2024-9392: Compromised content process can bypass site isolation (bmo#1899154, bmo#1905843)
    - CVE-2024-9393: Cross-origin access to PDF contents through multipart responses (bmo#1918301)
    - CVE-2024-9394: Cross-origin access to JSON contents through multipart responses (bmo#1918874)
    - CVE-2024-8900: Clipboard write permission bypass (bmo#1872841)
    - CVE-2024-9396: Potential memory corruption may occur when cloning certain objects (bmo#1912471)
    - CVE-2024-9397: Potential directory upload bypass via clickjacking (bmo#1916659)
    - CVE-2024-9398: External protocol handlers could be enumerated via popups (bmo#1881037)
    - CVE-2024-9399: Specially crafted WebTransport requests could lead to denial of service (bmo#1907726)
    - CVE-2024-9400: Potential memory corruption during JIT compilation (bmo#1915249)
    - CVE-2024-9401: Memory safety bugs fixed in Firefox 131, Firefox ESR 115.16, Firefox ESR 128.3,
    Thunderbird 131, and Thunderbird 128.3 (bmo#1872744, bmo#1897792, bmo#1911317, bmo#1916476)
    - CVE-2024-9402: Memory safety bugs fixed in Firefox 131, Firefox ESR 128.3, Thunderbird 131, and
    Thunderbird 128.3i  (bmo#1872744, bmo#1897792, bmo#1911317, bmo#1913445, bmo#1914106, bmo#1914475,
    bmo#1914963, bmo#1915008, bmo#1916476)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231413");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-October/019592.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d9a46e6");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9392");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9393");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9394");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9396");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9397");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9398");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9400");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9401");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9680");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-devel and / or MozillaFirefox-translations-common packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9680");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaFirefox-128.3.1-112.231.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'MozillaFirefox-devel-128.3.1-112.231.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'MozillaFirefox-translations-common-128.3.1-112.231.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'MozillaFirefox-devel-128.3.1-112.231.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'MozillaFirefox-128.3.1-112.231.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'MozillaFirefox-translations-common-128.3.1-112.231.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.5']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-devel / etc');
}
