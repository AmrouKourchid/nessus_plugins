#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-c729dabeb1
#

include('compat.inc');

if (description)
{
  script_id(194657);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2015-20107", "CVE-2021-28861", "CVE-2023-24329");
  script_xref(name:"FEDORA", value:"2023-c729dabeb1");

  script_name(english:"Fedora 40 : pypy3.10 (2023-c729dabeb1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-c729dabeb1 advisory.

    Automatic update for pypy3.10-7.3.12-1.3.10.fc40.

    ##### **Changelog**

    ```
    * Wed Jul 26 2023 Miro Hronok <mhroncok@redhat.com> - 7.3.12-1.3.10
    - Initial PyPy 3.10 package
    * Wed Jul 26 2023 Miro Hronok <mhroncok@redhat.com> - 7.3.12-1.3.9
    - Update to 7.3.12
    - Fixes: rhbz#2203423
    * Fri Jul 21 2023 Fedora Release Engineering <releng@fedoraproject.org> - 7.3.11-5.3.9
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_39_Mass_Rebuild
    * Mon May 29 2023 Charalampos Stratakis <cstratak@redhat.com> - 7.3.11-4.3.9
    - Security fix for CVE-2023-24329
    Resolves: rhbz#2174020
    * Fri Feb 17 2023 Miro Hronok <mhroncok@redhat.com> - 7.3.11-3.3.9
    - On Fedora 38+, obsolete the pypy3.8 package which is no longer available
    * Fri Jan 20 2023 Fedora Release Engineering <releng@fedoraproject.org> - 7.3.11-2.3.9
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild
    * Fri Dec 30 2022 Miro Hronok <mhroncok@redhat.com> - 7.3.11-1.3.9
    - Update to 7.3.11
    - Fixes: rhbz#2147520
    * Fri Dec  2 2022 Miro Hronok <mhroncok@redhat.com> - 7.3.9-5.3.9
    - On Fedora 37+, obsolete the pypy3.7 package which is no longer available
    * Mon Oct 10 2022 Lumr Balhar <lbalhar@redhat.com> - 7.3.9-4.3.9
    - Backport fix for CVE-2021-28861
    Resolves: rhbz#2120789
    * Fri Jul 22 2022 Fedora Release Engineering <releng@fedoraproject.org> - 7.3.9-3.3.9
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild
    * Tue Jun 28 2022 Charalampos Stratakis <cstratak@redhat.com> - 7.3.9-2.3.9
    - Security fix for CVE-2015-20107
    - Fixes: rhbz#2075390
    * Wed Mar 30 2022 Miro Hronok <mhroncok@redhat.com> - 7.3.9-1.3.9
    - Update to 7.3.9
    - Fixes: rhbz#2069873
    * Tue Mar  1 2022 Miro Hronok <mhroncok@redhat.com> - 7.3.8-1.3.9
    - Include the Python version in Release to workaround debuginfo conflicts
      and make same builds of different PyPy sort in a predictable way (e.g. wrt Obsoletes)
    - Namespace the debugsources to fix installation conflict with other PyPys
    - Fixes: rhbz#2053880
    - This is now the main PyPy 3 on Fedora 36+
    - Fixes: rhbz#2059670
    * Tue Feb 22 2022 Miro Hronok <mhroncok@redhat.com> - 7.3.8-1
    - Update to 7.3.8 final
    * Fri Feb 11 2022 Miro Hronok <mhroncok@redhat.com> - 7.3.8~rc2-1
    - Update to 7.3.8rc2
    * Wed Jan 26 2022 Miro Hronok <mhroncok@redhat.com> - 7.3.8~rc1-1
    - Update to 7.3.8rc1
    - Move to a CPython-like installation layout
    - Stop requiring pypy3.9 from pypy3.9-libs
    - Split tests into pypy3.9-test
    * Fri Jan 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 7.3.7-3
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild
    * Sat Jan  8 2022 Miro Hronok <mhroncok@redhat.com> - 7.3.7-2
    - Rebuilt for https://fedoraproject.org/wiki/Changes/LIBFFI34
    * Thu Nov 11 2021 Miro Hronok <mhroncok@redhat.com> - 7.3.7-1
    - Initial pypy3.8 package
    - Supplement tox
    * Tue Oct 26 2021 Tom Hrniar <thrnciar@redhat.com> - 7.3.6-1
    - Update to 7.3.6
    - Remove windows executable binaries
    - Fixes: rhbz#2003682
    * Mon Sep 20 2021 Miro Hronok <mhroncok@redhat.com> - 7.3.5-2
    - Explicitly buildrequire OpenSSL 1.1, as Python 3.7 is not compatible with OpenSSL 3.0
    * Mon Aug 16 2021 Miro Hronok <mhroncok@redhat.com> - 7.3.5-1
    - Update to 7.3.5
    - Fixes: rhbz#1992600
    * Mon Aug  9 2021 Tomas Hrnciar <thrnciar@redhat.com> - 7.3.4-4
    - Rename pypy3 to pypy3.7
    - pypy-stackless was removed

    ```

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-c729dabeb1");
  script_set_attribute(attribute:"solution", value:
"Update the affected pypy3.10 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-20107");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pypy3.10");
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
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'pypy3.10-7.3.12-1.3.10.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pypy3.10');
}
