#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:0111-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170250);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id(
    "CVE-2022-46871",
    "CVE-2022-46877",
    "CVE-2023-23598",
    "CVE-2023-23601",
    "CVE-2023-23602",
    "CVE-2023-23603",
    "CVE-2023-23605"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:0111-1");

  script_name(english:"SUSE SLES12 Security Update : MozillaFirefox (SUSE-SU-2023:0111-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:0111-1 advisory.

  - An out of date library (libusrsctp) contained vulnerabilities that could potentially be exploited. This
    vulnerability affects Firefox < 108. (CVE-2022-46871)

  - By confusing the browser, the fullscreen notification could have been delayed or suppressed, resulting in
    potential user confusion or spoofing attacks. This vulnerability affects Firefox < 108. (CVE-2022-46877)

  - Due to the Firefox GTK wrapper code's use of text/plain for drag data and GTK treating all text/plain
    MIMEs containing file URLs as being dragged a website could arbitrarily read a file via a call to
    <code>DataTransfer.setData</code>. This vulnerability affects Firefox < 109, Thunderbird < 102.7, and
    Firefox ESR < 102.7. (CVE-2023-23598)

  - Navigations were being allowed when dragging a URL from a cross-origin iframe into the same tab which
    could lead to website spoofing attacks. This vulnerability affects Firefox < 109, Thunderbird < 102.7, and
    Firefox ESR < 102.7. (CVE-2023-23601)

  - A mishandled security check when creating a WebSocket in a WebWorker caused the Content Security Policy
    connect-src header to be ignored. This could lead to connections to restricted origins from inside
    WebWorkers. This vulnerability affects Firefox < 109, Thunderbird < 102.7, and Firefox ESR < 102.7.
    (CVE-2023-23602)

  - Regular expressions used to filter out forbidden properties and values from style directives in calls to
    <code>console.log</code> weren't accounting for external URLs. Data could then be potentially exfiltrated
    from the browser. This vulnerability affects Firefox < 109, Thunderbird < 102.7, and Firefox ESR < 102.7.
    (CVE-2023-23603)

  - Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 108 and
    Firefox ESR 102.6. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox <
    109, Thunderbird < 102.7, and Firefox ESR < 102.7. (CVE-2023-23605)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-46871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-46877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23605");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-January/013492.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?355444f4");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-devel and / or MozillaFirefox-translations-common packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23605");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/21");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaFirefox-102.7.0-112.145.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'MozillaFirefox-devel-102.7.0-112.145.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'MozillaFirefox-translations-common-102.7.0-112.145.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'MozillaFirefox-102.7.0-112.145.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'MozillaFirefox-devel-102.7.0-112.145.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'MozillaFirefox-translations-common-102.7.0-112.145.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'MozillaFirefox-102.7.0-112.145.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'MozillaFirefox-devel-102.7.0-112.145.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'MozillaFirefox-translations-common-102.7.0-112.145.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.5']}
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
