#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-74c4c65ff6
#

include('compat.inc');

if (description)
{
  script_id(211005);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2022-1996",
    "CVE-2022-24675",
    "CVE-2022-27191",
    "CVE-2022-28327",
    "CVE-2022-29526",
    "CVE-2022-30629",
    "CVE-2022-41723"
  );
  script_xref(name:"FEDORA", value:"2024-74c4c65ff6");

  script_name(english:"Fedora 41 : google-guest-agent (2024-74c4c65ff6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 41 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2024-74c4c65ff6 advisory.

    Automatic update for google-guest-agent-20240314.00-4.fc41.

    ##### **Changelog**

    ```
    * Wed Apr 10 2024 Major Hayden <major@redhat.com> - 20240314.00-4
    - Skip events test
    * Wed Apr 10 2024 Major Hayden <major@redhat.com> - 20240314.00-3
    - Fix typo in License filename
    * Wed Apr 10 2024 Major Hayden <major@redhat.com> - 20240314.00-2
    - Sync packit config with other GCP pkgs
    * Wed Apr 10 2024 Major Hayden <major@redhat.com> - 20240314.00-1
    - Update to 20240314.00 rhbz#2274184
    * Wed Apr 10 2024 Fedora Release Engineering <releng@fedoraproject.org> - 20230726.00-8
    - Unretirement Releng Request: https://pagure.io/releng/issue/12057
    * Sun Feb 11 2024 Maxwell G <maxwell@gtmx.me> - 20230726.00-7
    - Rebuild for golang 1.22.0
    * Wed Jan 24 2024 Fedora Release Engineering <releng@fedoraproject.org> - 20230726.00-6
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild
    * Sat Jan 20 2024 Fedora Release Engineering <releng@fedoraproject.org> - 20230726.00-5
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild
    * Wed Sep  6 2023 Major Hayden <major@redhat.com> - 20230726.00-4
    - PRs to rawhide only
    * Fri Jul 28 2023 Major Hayden <major@redhat.com> - 20230726.00-3
    - Fix typo on ppc64le
    * Fri Jul 28 2023 Major Hayden <major@redhat.com> - 20230726.00-2
    - Disable ppc64/s390x arches
    * Fri Jul 28 2023 Packit <hello@packit.dev> - 20230726.00-1
    - [packit] 20230726.00 upstream release
    * Tue Jul 25 2023 Major Hayden <major@redhat.com> - 20230725.00-2
    - Disable koji auto build with packit
    * Tue Jul 25 2023 Packit <hello@packit.dev> - 20230725.00-1
    - [packit] 20230725.00 upstream release
    * Thu Jul 20 2023 Fedora Release Engineering <releng@fedoraproject.org> - 20230711.00-2
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_39_Mass_Rebuild
    * Wed Jul 12 2023 Major Hayden <major@redhat.com> - 20230711.00-1
    - Update to 20230711.00 rhbz#2222161
    * Wed Jul 12 2023 Major Hayden <major@redhat.com> - 20230707.00-2
    - Add packit config 
    * Tue Jul 11 2023 Major Hayden <major@redhat.com> - 20230707.00-1
    - Update to 20230707.00 rhbz#2221432
    * Mon Jul  3 2023 Major Hayden <major@redhat.com> - 20230628.00-1
    - Update to 20230628.00 rhbz#2218708
    * Wed Jun 28 2023 Major Hayden <major@redhat.com> - 20230626.00-1
    - Update to 20230626.00 rhbz#2218220
    * Mon Jun 12 2023 Major Hayden <major@redhat.com> - 20230601.00-1
    - Update to 20230601.00 rhbz#2211674
    * Thu May 18 2023 Major Hayden <major@redhat.com> - 20230517.00-1
    - Update to 20230517.00 rhbz#2208103
    * Mon May 15 2023 Major Hayden <major@redhat.com> - 20230510.00-1
    - Update to 20230510.00 rhbz#2198979
    * Mon May  1 2023 Major Hayden <major@redhat.com> - 20230426.00-1
    - Update to 20230426.00 rhbz#2190065
    * Thu Apr  6 2023 Major Hayden <major@redhat.com> - 20230403.00-1
    - Update to 20230403.00 rhbz#2183053
    * Tue Mar 28 2023 Major Hayden <major@redhat.com> - 20230221.00-2
    - Bump revision for rebuild rhbz#2178465
    * Tue Feb 28 2023 Major Hayden <major@redhat.com> - 20230221.00-1
    - Update to 20230221.00 rhbz#2172749
    * Wed Feb 22 2023 Major Hayden <major@redhat.com> - 20230207.00-2
    - Set SPDX license
    * Mon Feb 13 2023 Major Hayden <major@redhat.com> - 20230207.00-1
    - Update to 20230207.00 rhbz#2160637
    * Thu Jan 19 2023 Fedora Release Engineering <releng@fedoraproject.org> - 20221109.00-2
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild
    * Mon Nov 14 2022 Major Hayden <major@redhat.com> - 20221109.00-1
    - Update to 20221109.00 rhbz#2140412
    * Wed Oct 26 2022 Major Hayden <major@redhat.com> - 20221025.00-1
    - Update to 20221025.00 rhbz#2136314
    * Wed Oct 12 2022 Major Hayden <major@redhat.com> - 20220927.00-1
    - Update to 20220927.00 rhbz#2130931
    * Thu Aug 25 2022 Major Hayden <major@redhat.com> - 20220824.00-1
    - Update to 20220824.00 rhbz#2120895
    * Thu Aug 18 2022 Major Hayden <major@redhat.com> - 20220816.01-1
    - Update to 20220816.01 rhbz#2119456
    * Thu Jul 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 20201217.02-6
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild
    * Tue Jul 19 2022 Maxwell G <gotmax@e.email> - 20201217.02-5
    - Rebuild for
      CVE-2022-{1705,32148,30631,30633,28131,30635,30632,30630,1962} in golang
    * Sat Jun 18 2022 Robert-Andr Mauchin <zebob.m@gmail.com> - 20201217.02-4
    - Rebuilt for CVE-2022-1996, CVE-2022-24675, CVE-2022-28327,
      CVE-2022-27191, CVE-2022-29526, CVE-2022-30629

    ```

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-74c4c65ff6");
  script_set_attribute(attribute:"solution", value:
"Update the affected google-guest-agent package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1996");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:google-guest-agent");
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
if (! preg(pattern:"^41([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 41', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'google-guest-agent-20240314.00-4.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'google-guest-agent');
}
