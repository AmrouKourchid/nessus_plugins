#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-2487.
##

include('compat.inc');

if (description)
{
  script_id(175702);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2022-3287",
    "CVE-2022-34301",
    "CVE-2022-34302",
    "CVE-2022-34303"
  );

  script_name(english:"Oracle Linux 9 : fwupd (ELSA-2023-2487)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-2487 advisory.

    [1.8.10-2.0.1]
    - Drop pesign.service restart in postun [Orabug: 34760075]
    - Update signing certificate [JIRA: OLDIS-16371]
    - Rebuild for SecureBoot signatures [Orabug: 33801813]
    - Build with the updated Oracle certificate
    - Use oraclesecureboot301 as certdir [Orabug: 29881368]
    - Use new signing certificate (Alex Burmashev)
    - Update SBAT data to include Oracle [Oracle: 33072886]

    [1.8.10-2]
    - Rebuild because distrobaker did entirely the wrong thing.
    - Resolves: rhbz#2128384, needed for rhbz#2119436 and rhbz#2128384

    [1.8.10-1]
    - Rebase to latest upstream release to fix multiple ESP detection problems
    - Resolves: rhbz#2128384, needed for rhbz#2119436 and rhbz#2128384

    [1.7.10-1]
    - New upstream release
    - Resolves: rhbz#2129280

    [1.7.9-2]
    - Include the new dbx updates on the filesystem; clients typically do not have LVFS enabled.
    - Resolves: rhbz#2120708

    [1.7.8-1]
    - New upstream release
    - Resolves: rhbz#2059075

    [1.7.4-3]
    - Disable the Logitech bulkcontroller plugin to avoid adding a dep to protobuf-c
      which lives in AppStream, not BaseOS.
    - Use the efi_vendor variable from EFI-RPM
    - Resolves: rhbz#2064904

    [1.7.4-1]
    - New upstream release
    - Backport Fedora 34 changes
    - Include support for Lenovo TBT4 Docking stations
    - Do not cause systemd-modules-load failures
    - Build against a new enough pesign
    - Resolves: rhbz#2007520

    [1.7.1-1]
    - New upstream release
    - Backport Fedora 34 changes
    - Include support for Dell TBT4 Docking stations
    - Resolves: rhbz#1974347
    - Resolves: rhbz#1991426

    [1.5.9-4]
    - Rebuilt to use redhatsecureboot503 signatures
    - Undo last Fedora sync to use the RHEL-specific patches
    - Resolves: rhbz#2007520

    [1.5.9-3]
    - Rebuilt for IMA sigs, glibc 2.34, aarch64 flags
      Related: rhbz#1991688

    [1.5.9-2]
    - Rebuilt for RHEL 9 BETA for openssl 3.0
      Related: rhbz#1971065

    [1.5.9-1]
    - Rebase to include the SBAT metadata section to allow fixing BootHole
    - Resolves: rhbz#1951030

    [1.5.5-4]
    - Rebuilt for RHEL 9 BETA on Apr 15th 2021. Related: rhbz#1947937

    [1.5.5-3]
    - Backport a patch from master to drop the python3-pillow dep
    - Resolves: rhbz#1935838

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-2487.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected fwupd, fwupd-devel and / or fwupd-plugin-flashrom packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3287");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-34303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fwupd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fwupd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fwupd-plugin-flashrom");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'fwupd-1.8.10-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fwupd-devel-1.8.10-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fwupd-plugin-flashrom-1.8.10-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fwupd-1.8.10-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fwupd-devel-1.8.10-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fwupd-plugin-flashrom-1.8.10-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fwupd / fwupd-devel / fwupd-plugin-flashrom');
}
