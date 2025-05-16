#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-a267e93f8c
#

include('compat.inc');

if (description)
{
  script_id(194556);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2024-1753");
  script_xref(name:"FEDORA", value:"2024-a267e93f8c");

  script_name(english:"Fedora 40 : containers-common / netavark / podman (2024-a267e93f8c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2024-a267e93f8c advisory.

    Security fix for CVE-2024-1753

    Automatic update for podman-5.0.0-1.fc40.

    ##### **Changelog for podman**

    ```
    * Tue Mar 19 2024 Packit <hello@packit.dev> - 5:5.0.0-1
    - [packit] 5.0.0 upstream release

    * Fri Mar 15 2024 Packit <hello@packit.dev> - 5:5.0.0~rc7-1
    - [packit] 5.0.0-rc7 upstream release

    * Wed Mar 13 2024 Lokesh Mandvekar <lsm5@redhat.com> - 5:5.0.0~rc6-2
    - Resolves: #2269148 - make passt a hard dep

    * Mon Mar 11 2024 Packit <hello@packit.dev> - 5:5.0.0~rc6-1
    - [packit] 5.0.0-rc6 upstream release

    * Fri Mar 08 2024 Packit <hello@packit.dev> - 5:5.0.0~rc5-1
    - [packit] 5.0.0-rc5 upstream release

    * Tue Mar 05 2024 Packit <hello@packit.dev> - 5:5.0.0~rc4-1
    - [packit] 5.0.0-rc4 upstream release

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-5
    - Show the toolbox RPMs used to run the tests

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-4
    - Avoid running out of storage space when running the Toolbx tests

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-3
    - Silence warnings about deprecated grep(1) use in test logs

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-2
    - Update how Toolbx is spelt

    * Thu Feb 22 2024 Packit <hello@packit.dev> - 5:5.0.0~rc3-1
    - [packit] 5.0.0-rc3 upstream release

    ```

    ----

    Automatic update for podman-5.0.0~rc7-1.fc40.

    ##### **Changelog for podman**

    ```
    * Fri Mar 15 2024 Packit <hello@packit.dev> - 5:5.0.0~rc7-1
    - [packit] 5.0.0-rc7 upstream release

    * Wed Mar 13 2024 Lokesh Mandvekar <lsm5@redhat.com> - 5:5.0.0~rc6-2
    - Resolves: #2269148 - make passt a hard dep

    * Mon Mar 11 2024 Packit <hello@packit.dev> - 5:5.0.0~rc6-1
    - [packit] 5.0.0-rc6 upstream release

    * Fri Mar 08 2024 Packit <hello@packit.dev> - 5:5.0.0~rc5-1
    - [packit] 5.0.0-rc5 upstream release

    * Tue Mar 05 2024 Packit <hello@packit.dev> - 5:5.0.0~rc4-1
    - [packit] 5.0.0-rc4 upstream release

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-5
    - Show the toolbox RPMs used to run the tests

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-4
    - Avoid running out of storage space when running the Toolbx tests

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-3
    - Silence warnings about deprecated grep(1) use in test logs

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-2
    - Update how Toolbx is spelt

    * Thu Feb 22 2024 Packit <hello@packit.dev> - 5:5.0.0~rc3-1
    - [packit] 5.0.0-rc3 upstream release

    ```



    ----

    make passt and netavark hard dependencies for podman

    ----

    Automatic update for podman-5.0.0~rc6-1.fc40.

    ##### **Changelog for podman**

    ```
    * Mon Mar 11 2024 Packit <hello@packit.dev> - 5:5.0.0~rc6-1
    - [packit] 5.0.0-rc6 upstream release

    * Fri Mar 08 2024 Packit <hello@packit.dev> - 5:5.0.0~rc5-1
    - [packit] 5.0.0-rc5 upstream release

    * Tue Mar 05 2024 Packit <hello@packit.dev> - 5:5.0.0~rc4-1
    - [packit] 5.0.0-rc4 upstream release

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-5
    - Show the toolbox RPMs used to run the tests

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-4
    - Avoid running out of storage space when running the Toolbx tests

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-3
    - Silence warnings about deprecated grep(1) use in test logs

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-2
    - Update how Toolbx is spelt

    * Thu Feb 22 2024 Packit <hello@packit.dev> - 5:5.0.0~rc3-1
    - [packit] 5.0.0-rc3 upstream release

    ```

    ----

    Automatic update for podman-5.0.0~rc5-1.fc40.

    ##### **Changelog for podman**

    ```
    * Fri Mar 08 2024 Packit <hello@packit.dev> - 5:5.0.0~rc5-1
    - [packit] 5.0.0-rc5 upstream release

    * Tue Mar 05 2024 Packit <hello@packit.dev> - 5:5.0.0~rc4-1
    - [packit] 5.0.0-rc4 upstream release

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-5
    - Show the toolbox RPMs used to run the tests

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-4
    - Avoid running out of storage space when running the Toolbx tests

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-3
    - Silence warnings about deprecated grep(1) use in test logs

    * Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-2
    - Update how Toolbx is spelt

    * Thu Feb 22 2024 Packit <hello@packit.dev> - 5:5.0.0~rc3-1
    - [packit] 5.0.0-rc3 upstream release

    ```

    ----

    Automatic update for podman-5.0.0~rc4-1.fc40.

    ----

    Automatic update for podman-5.0.0~rc3-1.fc40.

    ----

    Removing podman 5.0.0-rc6 build to let the rest of this get past gating. We already have v5.0.0 bodhi for
    f40.


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-a267e93f8c");
  script_set_attribute(attribute:"solution", value:
"Update the affected 5:containers-common, 5:podman and / or netavark packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1753");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:netavark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:podman");
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
    {'reference':'containers-common-0.58.0-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE, 'epoch':'5'},
    {'reference':'netavark-1.10.3-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'podman-5.0.0-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE, 'epoch':'5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'containers-common / netavark / podman');
}
