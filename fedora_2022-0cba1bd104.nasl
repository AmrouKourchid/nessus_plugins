#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-0cba1bd104
#

include('compat.inc');

if (description)
{
  script_id(211197);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2021-3281",
    "CVE-2021-23336",
    "CVE-2021-28658",
    "CVE-2021-31542"
  );
  script_xref(name:"FEDORA", value:"2022-0cba1bd104");

  script_name(english:"Fedora 38 : python-django3 (2022-0cba1bd104)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-0cba1bd104 advisory.

    Automatic update for python-django3-3.2.15-1.fc38.

    ##### **Changelog**

    ```
    * Tue Oct  4 2022 Michel Alexandre Salim <salimma@fedoraproject.org> -
    3.2.15-1
    - Initial python-django3 release
    * Sun Oct  2 2022 Michel Alexandre Salim <salimma@fedoraproject.org> - 3.2.9-6
    - Fork to python-django3, needed by the Mailman stack
    * Fri Jan 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 3.2.9-5
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild
    * Fri Dec 17 2021 Michel Alexandre Salim <salimma@fedoraproject.org> - 3.2.9-4
    - Drop obsolete python_provide lines
    * Wed Dec 15 2021 Michel Alexandre Salim <salimma@fedoraproject.org> - 3.2.9-3
    - Use build-dependency generator
    - Use pyproject macros
    * Wed Dec 15 2021 Michel Alexandre Salim <salimma@fedoraproject.org> - 3.2.9-2
    - Drop old BR on python3-mock
    * Wed Nov 24 2021 Karolina Surma <ksurma@redhat.com> - 3.2.9-1
    - update to 3.2.9
    - unskip fixed tests
    - backport fix for building docs with python-sphinx 4.3.0
    * Wed Sep  8 2021 Matthias Runge <mrunge@redhat.com> - 3.2.7-1
    - update to 3.2.7 (rhbz#1999958)
    * Mon Aug  9 2021 Matthias Runge <mrunge@redhat.com> - 3.2.6-1
    - update to 3.2.6 (rhbz#1957630)
    - skip failing test AssertionError: Error: invalid choice: 'test'
      (choose from 'foo')(rhbz#1898084)
    * Tue Jul 27 2021 Fedora Release Engineering <releng@fedoraproject.org> - 3.2.1-3
    - Second attempt - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_35_Mass_Rebuild
    * Fri Jun  4 2021 Python Maint <python-maint@redhat.com> - 3.2.1-2
    - Rebuilt for Python 3.10
    * Tue May  4 2021 Matthias Runge <mrunge@redhat.com> - 3.2.1-1
    - rebase to 3.2.1, fixes CVE-2021-31542
    - rebase to 3.1.8 fixes CVE-2021-28658 (rbhz#1946580)
    - rebase to 3.2.1 (rhbz#1917820)
    * Fri Mar  5 2021 Matthias Runge <mrunge@redhat.com> - 3.1.7-1
    - update to 3.1.7, fix CVE-2021-23336 (rhbz#1931542)
    * Thu Feb  4 2021 Matthias Runge <mrunge@redhat.com> - 3.1.6-1
    - update to 3.1.6, fix CVE-2021-3281 (rhbz#1923734)
    * Wed Jan 27 2021 Fedora Release Engineering <releng@fedoraproject.org> - 3.1.5-2
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild
    * Mon Jan  4 2021 Matthias Runge <mrunge@redhat.com> - 3.1.5-1
    - update to 3.1.5
    * Thu Dec  3 2020 Matthias Runge <mrunge@redhat.com> - 3.1.4-1
    - update to 3.1.4 (rhbz#1893635)

    ```

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-0cba1bd104");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-django3 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3281");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-31542");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-django3");
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
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'python-django3-3.2.15-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-django3');
}
