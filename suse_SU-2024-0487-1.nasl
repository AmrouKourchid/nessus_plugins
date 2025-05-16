#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0487-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(190632);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/19");

  script_cve_id(
    "CVE-2020-7753",
    "CVE-2021-3807",
    "CVE-2021-3918",
    "CVE-2021-43138",
    "CVE-2021-43798",
    "CVE-2021-43815",
    "CVE-2022-0155",
    "CVE-2022-41715"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0487-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : SUSE Manager Client Tools (SUSE-SU-2024:0487-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:0487-1 advisory.

  - All versions of package trim are vulnerable to Regular Expression Denial of Service (ReDoS) via trim().
    (CVE-2020-7753)

  - ansi-regex is vulnerable to Inefficient Regular Expression Complexity (CVE-2021-3807)

  - json-schema is vulnerable to Improperly Controlled Modification of Object Prototype Attributes ('Prototype
    Pollution') (CVE-2021-3918)

  - In Async before 2.6.4 and 3.x before 3.2.2, a malicious user can obtain privileges via the mapValues()
    method, aka lib/internal/iterator.js createObjectIterator prototype pollution. (CVE-2021-43138)

  - Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through
    8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files.
    The vulnerable URL path is: `<grafana_host_url>/public/plugins//`, where is the plugin ID for any
    installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched
    versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about
    vulnerable URL paths, mitigation, and the disclosure timeline. (CVE-2021-43798)

  - Grafana is an open-source platform for monitoring and observability. Grafana prior to versions 8.3.2 and
    7.5.12 has a directory traversal for arbitrary .csv files. It only affects instances that have the
    developer testing tool called TestData DB data source enabled and configured. The vulnerability is limited
    in scope, and only allows access to files with the extension .csv to authenticated users only. Grafana
    Cloud instances have not been affected by the vulnerability. Versions 8.3.2 and 7.5.12 contain a patch for
    this issue. There is a workaround available for users who cannot upgrade. Running a reverse proxy in front
    of Grafana that normalizes the PATH of the request will mitigate the vulnerability. The proxy will have to
    also be able to handle url encoded paths. (CVE-2021-43815)

  - follow-redirects is vulnerable to Exposure of Private Personal Information to an Unauthorized Actor
    (CVE-2022-0155)

  - Programs which compile regular expressions from untrusted sources may be vulnerable to memory exhaustion
    or denial of service. The parsed regexp representation is linear in the size of the input, but in some
    cases the constant factor can be as high as 40,000, making relatively small regexps consume much larger
    amounts of memory. After fix, each regexp being parsed is limited to a 256 MB memory footprint. Regular
    expressions whose representation would use more space than that are rejected. Normal use of regular
    expressions is unaffected. (CVE-2022-41715)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218844");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-February/017931.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a07ee69a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-7753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41715");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang-github-lusitaniae-apache_exporter, prometheus-postgres_exporter and / or spacecmd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3918");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-lusitaniae-apache_exporter");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'golang-github-lusitaniae-apache_exporter-1.0.0-150000.1.20.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'golang-github-lusitaniae-apache_exporter-1.0.0-150000.1.20.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'prometheus-postgres_exporter-0.10.1-150000.1.17.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'spacecmd-4.3.26-150000.3.113.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-github-lusitaniae-apache_exporter / etc');
}
