#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-6a9dc1d46b
#

include('compat.inc');

if (description)
{
  script_id(211087);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2021-31215",
    "CVE-2021-43337",
    "CVE-2022-29500",
    "CVE-2022-29501",
    "CVE-2022-29502"
  );
  script_xref(name:"FEDORA", value:"2022-6a9dc1d46b");

  script_name(english:"Fedora 38 : slurm (2022-6a9dc1d46b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-6a9dc1d46b advisory.

    Automatic update for slurm-22.05.6-1.fc38.

    ##### **Changelog**

    ```
    * Sun Nov 27 2022 Philip Kovacs <pkfed@fedoraproject.org> - 22.05.6-1
    - Update to 22.05.6 (#2131112)
    - Update deprecated vars in slurm.conf (#2133159)
    * Tue Sep  6 2022 Philip Kovacs <pkfed@fedoraproject.org> - 22.05.3-2
    - Add slurm to epel9 (#2072632); update spec for epel 7/8/9
    - Use * Mon Nov 28 2022 Fedora Project - 22.05.6-1.fc38
    - local build macro; add changelog file
    * Mon Sep  5 2022 Philip Kovacs <pkfed@fedoraproject.org> - 22.05.3-1
    - Update to 22.05.3
    - Thanks Cristian Le (fedora@lecris.me) for his contributions
    * Sat Jul 23 2022 Fedora Release Engineering <releng@fedoraproject.org> - 21.08.8-4
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild
    * Mon May 30 2022 Jitka Plesnikova <jplesnik@redhat.com> - 21.08.8-3
    - Perl 5.36 rebuild
    * Mon May  9 2022 Philip Kovacs <pkfed@fedoraproject.org> - 21.08.8-2
    - Update to 21.08.8-2 (upstream re-release)
    * Thu May  5 2022 Carl George <carl@george.computer> - 21.08.8-1
    - Update to 21.08.8, resolves: rhbz#2082276
    - Fix CVE-2022-29500, resolves: rhbz#2082286
    - Fix CVE-2022-29501, resolves: rhbz#2082289
    - Fix CVE-2022-29502, resolves: rhbz#2082293
    * Sat Apr  2 2022 Philip Kovacs <pkfed@fedoraproject.org> - 21.08.6-1
    - Update to 21.08.6
    * Sat Jan 22 2022 Fedora Release Engineering <releng@fedoraproject.org> - 21.08.5-2
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild
    * Fri Jan 14 2022 Philip Kovacs <pkfed@fedoraproject.org> - 21.08.5-1
    - Update to 21.08.5
    * Sun Nov 21 2021 Orion Poplawski <orion@nwra.com> - 21.08.4-2
    - Rebuild for hdf5 1.12.1
    * Wed Nov 17 2021 Philip Kovacs <pkfed@fedoraproject.org> - 21.08.4-1
    - Update to 21.08.4
    - Closes security issue CVE-2021-43337
    * Sun Oct 31 2021 Philip Kovacs <pkfed@fedoraproject.org> - 21.08.2-2
    - Correct log rotation problems (#2016683, #2018508)
    * Fri Oct  8 2021 Philip Kovacs <pkfed@fedoraproject.org> - 21.08.2-1
    - Update to 21.08.2
    - Added Fedora patches to support pmix v4
    - Remove slurm-pmi(-devel) subpackages
    * Tue Aug 10 2021 Orion Poplawski <orion@nwra.com> - 20.11.8-4
    - Rebuild for hdf5 1.10.7
    * Fri Jul 23 2021 Fedora Release Engineering <releng@fedoraproject.org> - 20.11.8-3
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_35_Mass_Rebuild
    * Sat Jul 10 2021 Bjrn Esser <besser82@fedoraproject.org> - 20.11.8-2
    - Rebuild for versioned symbols in json-c
    * Sat Jul  3 2021 Philip Kovacs <pkfed@fedoraproject.org> - 20.11.8-1
    - Update to 20.11.8
    * Tue May 25 2021 Jitka Plesnikova <jplesnik@redhat.com> - 20.11.7-4
    - Perl 5.34 re-rebuild updated packages
    * Mon May 24 2021 Philip Kovacs <pkfed@fedoraproject.org> - 20.11.7-3
    - Move auth_jwt.so plugin to base package (#1947878)
    * Fri May 21 2021 Jitka Plesnikova <jplesnik@redhat.com> - 20.11.7-2
    - Perl 5.34 rebuild
    * Sat May 15 2021 Philip Kovacs <pkfed@fedoraproject.org> - 20.11.7-1
    - Update to 20.11.7
    - Closes security issue CVE-2021-31215
    * Tue May  4 2021 Philip Kovacs <pkfed@fedoraproject.org> - 20.11.6-1
    - Release of 20.11.6
    * Mon Apr 12 2021 Philip Kovacs <pkfed@fedoraproject.org> - 20.11.5-2
    - Add subpackage slurm-slurmrestd (Slurm REST API daemon)
    * Fri Mar 26 2021 Philip Kovacs <pkfed@fedoraproject.org> - 20.11.5-1
    - Release of 20.11.5
    * Tue Mar  2 2021 Zbigniew Jdrzejewski-Szmek <zbyszek@in.waw.pl> - 20.11.3-3
    - Rebuilt for updated systemd-rpm-macros
      See https://pagure.io/fesco/issue/2583.
    * Wed Jan 27 2021 Fedora Release Engineering <releng@fedoraproject.org> - 20.11.3-2
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild
    * Tue Jan 19 2021 Philip Kovacs <pkfed@fedoraproject.org> - 20.11.3-1
    - Release of 20.11.3
    * Wed Jan  6 2021 Philip Kovacs <pkfed@fedoraproject.org> - 20.11.2-2
    - Minor spec adjustments
    * Tue Jan  5 2021 Philip Kovacs <pkfed@fedoraproject.org> - 20.11.2-1
    - Release of 20.11.2

    ```

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-6a9dc1d46b");
  script_set_attribute(attribute:"solution", value:
"Update the affected slurm package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29501");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-29502");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:slurm");
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
    {'reference':'slurm-22.05.6-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'slurm');
}
