#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# the CentOS Stream Build Service.
##

include('compat.inc');

if (description)
{
  script_id(193940);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/26");

  script_cve_id("CVE-2023-45803");

  script_name(english:"CentOS 9 : python-urllib3-1.26.5-5.el9");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update for python3-urllib3.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 9 host has a package installed that is affected by a vulnerability as referenced in the python-
urllib3-1.26.5-5.el9 build changelog.

  - urllib3 is a user-friendly HTTP client library for Python. urllib3 previously wouldn't remove the HTTP
    request body when an HTTP redirect response using status 301, 302, or 303 after the request had its method
    changed from one that could accept a request body (like `POST`) to `GET` as is required by HTTP RFCs.
    Although this behavior is not specified in the section for redirects, it can be inferred by piecing
    together information from different sections and we have observed the behavior in other major HTTP client
    implementations like curl and web browsers. Because the vulnerability requires a previously trusted
    service to become compromised in order to have an impact on confidentiality we believe the exploitability
    of this vulnerability is low. Additionally, many users aren't putting sensitive data in HTTP request
    bodies, if this is the case then this vulnerability isn't exploitable. Both of the following conditions
    must be true to be affected by this vulnerability: 1. Using urllib3 and submitting sensitive information
    in the HTTP request body (such as form data or JSON) and 2. The origin service is compromised and starts
    redirecting using 301, 302, or 303 to a malicious peer or the redirected-to service becomes compromised.
    This issue has been addressed in versions 1.26.18 and 2.0.7 and users are advised to update to resolve
    this issue. Users unable to update should disable redirects for services that aren't expecting to respond
    with redirects with `redirects=False` and disable automatic redirects with `redirects=False` and handle
    301, 302, and 303 redirects manually by stripping the HTTP request body. (CVE-2023-45803)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=44305");
  script_set_attribute(attribute:"solution", value:
"Update the CentOS 9 Stream python3-urllib3 package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:M/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-urllib3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'CentOS 9.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'python3-urllib3-1.26.5-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-urllib3');
}
