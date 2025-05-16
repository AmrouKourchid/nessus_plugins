#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-3256575fc8
#

include('compat.inc');

if (description)
{
  script_id(185336);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2022-24785", "CVE-2022-31129");
  script_xref(name:"FEDORA", value:"2023-3256575fc8");

  script_name(english:"Fedora 39 : python-notebook (2023-3256575fc8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 39 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-3256575fc8 advisory.

    Automatic update for python-notebook-7.0.0-1.fc39.

    ##### **Changelog**

    ```
    * Thu Jul 20 2023 Lumir Balhar <lbalhar@redhat.com> - 7.0.0-1
    - Update to 7.0.0 (rhbz#2224039)
    * Mon Jul 10 2023 Lumir Balhar <lbalhar@redhat.com> - 7.0.0rc2-1
    - Update to 7.0.0 RC2
    * Mon Jul 10 2023 Miro Hronok <miro@hroncok.cz> - 7.0.0b3-3
    - Workaround a possible Python 3.12 regression in importlib.resources
    * Tue Jul  4 2023 Python Maint <python-maint@redhat.com> - 7.0.0b3-2
    - Rebuilt for Python 3.12
    * Thu Jun  1 2023 Lumir Balhar <lbalhar@redhat.com> - 7.0.0b3-1
    - Update to 7.0.0 beta 3 (rhbz#2184443)
    * Wed Mar 29 2023 Lumir Balhar <lbalhar@redhat.com> - 7.0.0a18-1
    - Update to 7.0.0a18 (rhbz#2181597)
    * Wed Mar 22 2023 Lumir Balhar <lbalhar@redhat.com> - 7.0.0a17-1
    - Update to 7.0.0 alpha 17 (rhbz#2178583)
    * Fri Mar 10 2023 Lumir Balhar <lbalhar@redhat.com> - 7.0.0a15-1
    - Update to 7.0.0a15
    * Mon Mar  6 2023 Lumr Balhar <lbalhar@redhat.com> - 6.5.3-1
    - Update to 6.5.3 (rhbz#2062405)
    * Wed Feb  1 2023 Lumr Balhar <lbalhar@redhat.com> - 6.5.2-1
    - Update to 6.5.2 (#2062405)
    * Fri Jan 20 2023 Fedora Release Engineering <releng@fedoraproject.org> - 6.4.12-2
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild
    * Wed Aug  3 2022 Karolina Surma <ksurma@redhat.com> - 6.4.12-1
    - Update to 6.4.12
    * Fri Jul 22 2022 Fedora Release Engineering <releng@fedoraproject.org> - 6.4.11-4
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild
    * Wed Jul 13 2022 Miro Hronok <mhroncok@redhat.com> - 6.4.11-3
    - Fix CVE-2022-24785 and CVE-2022-31129 in bundled moment
    - Fixes: rhbz#2075263
    * Thu Jun 16 2022 Python Maint <python-maint@redhat.com> - 6.4.11-2
    - Rebuilt for Python 3.11
    * Mon May 30 2022 Miro Hronok <mhroncok@redhat.com> - 6.4.11-1
    - Update to 6.4.11
    * Tue Mar 22 2022 Miro Hronok <mhroncok@redhat.com> - 6.4.10-1
    - Update to 6.4.10
    * Tue Jan 25 2022 Miro Hronok <mhroncok@redhat.com> - 6.4.8-1
    - Update to 6.4.8
    - Fixes: rhbz#2045852
    * Tue Jan 25 2022 Miro Hronok <mhroncok@redhat.com> - 6.4.7-1
    - Update to 6.4.7
    - Fixes: rhbz#2039905
    * Fri Jan 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 6.4.6-3
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild
    * Mon Nov 29 2021 Karolina Surma <ksurma@redhat.com> - 6.4.6-2
    - Remove -s from Python shebang in `jupyter-*` executables
      to let Jupyter see pip installed extensions
    * Wed Nov 24 2021 Karolina Surma <ksurma@redhat.com> - 6.4.6-1
    - Update to 6.4.6
    Resolves: rhbz#2023994
    * Tue Oct 26 2021 Lumr Balhar <lbalhar@redhat.com> - 6.4.5-1
    - Update to 6.4.5
    Resolves: rhbz#2004590
    * Wed Aug 11 2021 Tomas Hrnciar <thrnciar@redhat.com> - 6.4.3-1
    - Update to 6.4.3
    - Fixes: rhbz#1990615
    - Fixes: rhbz#1992573
    * Fri Jul 23 2021 Fedora Release Engineering <releng@fedoraproject.org> - 6.4.0-3
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_35_Mass_Rebuild

    ```

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-3256575fc8");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-notebook package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24785");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-notebook");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'python-notebook-7.0.0-1.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-notebook');
}
