#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-e453a209e9
#

include('compat.inc');

if (description)
{
  script_id(207539);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/21");

  script_cve_id(
    "CVE-2023-27043",
    "CVE-2024-6232",
    "CVE-2024-7592",
    "CVE-2024-8088"
  );
  script_xref(name:"FEDORA", value:"2024-e453a209e9");

  script_name(english:"Fedora 39 : python3-docs / python3.12 (2024-e453a209e9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 39 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2024-e453a209e9 advisory.

    This is the sixth maintenance release of Python 3.12
    ====================================================

    Python 3.12 is the newest major release of the Python programming language, and it contains many new
    features and optimizations. 3.12.6 is the latest maintenance release, containing about 90 bugfixes, build
    improvements and documentation changes since 3.12.5. This is an expedited release to address the following
    security issues:

    -   [gh-123067](https://github.com/python/cpython/issues/123067): Fix quadratic complexity in parsing
    ``-quoted cookie values with backslashes by
    [`http.cookies`](https://docs.python.org/3/library/http.cookies.html#module-http.cookies). Fixes
    CVE-2024-7592.
    -   [gh-121285](https://github.com/python/cpython/issues/121285): Remove backtracking from tarfile header
    parsing for `hdrcharset`, PAX, and GNU sparse headers. That's CVE-2024-6232.
    -   [gh-102988](https://github.com/python/cpython/issues/102988): [`email.utils.getaddresses()`](https://d
    ocs.python.org/3/library/email.utils.html#email.utils.getaddresses) and
    [`email.utils.parseaddr()`](https://docs.python.org/3/library/email.utils.html#email.utils.parseaddr) now
    return `('', '')` 2-tuples in more situations where invalid email addresses are encountered instead of
    potentially inaccurate values. Add optional *strict* parameter to these two functions: use `strict=False`
    to get the old behavior, accept malformed inputs. `getattr(email.utils, 'supports_strict_parsing', False)`
    can be use to check if the *strict* paramater is available. This improves the CVE-2023-27043 fix.
    -   [gh-123270](https://github.com/python/cpython/issues/123270): Sanitize names in
    [`zipfile.Path`](https://docs.python.org/3/library/zipfile.html#zipfile.Path) to avoid infinite loops
    ([gh-122905](https://github.com/python/cpython/issues/122905)) without breaking contents using legitimate
    characters. That's CVE-2024-8088.

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-e453a209e9");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3-docs and / or python3.12 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27043");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python3-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python3.12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^39([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 39', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'python3-docs-3.12.6-1.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.12-3.12.6-1.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-docs / python3.12');
}
