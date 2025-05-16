#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-8434.
##

include('compat.inc');

if (description)
{
  script_id(168235);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2022-41032");

  script_name(english:"Oracle Linux 9 : dotnet7.0 (ELSA-2022-8434)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2022-8434 advisory.

    [7.0.100-0.5.rc2.0.1]
    - Set TargetRid based on os release major version, add OL arm64 RuntimeIdentifier [Orabug: 34671152]

    [7.0.100-0.5.rc2]
    - Add lldb as a build dependency
    - Related: RHBZ#2134641

    [7.0.100-0.4.rc2]
    - Enable ppc64le builds
    - Related: RHBZ#2134641

    [7.0.100-0.3.rc2]
    - Update to .NET 7 RC 2
    - Resolves: RHBZ#2134641

    [7.0.100-0.2.rc1]
    - Update to .NET 7 RC 1
    - Enable s390x builds
    - Resolves: RHBZ#2123884

    [7.0.100-0.1]
    - Initial .NET 7 package
    - Resolves: RHBZ#2112027

    [6.0.105-1]
    - Update to .NET SDK 6.0.105 and Runtime 6.0.5

    [6.0.104-1]
    - Update to .NET SDK 6.0.104 and Runtime 6.0.4

    [6.0.103-1]
    - Update to .NET SDK 6.0.103 and Runtime 6.0.3

    [6.0.102-1]
    - Update to .NET SDK 6.0.102 and Runtime 6.0.2

    [6.0.101-3]
    - Update to .NET SDK 6.0.101 and Runtime 6.0.1

    [6.0.100-3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild

    [6.0.100-2]
    - Disable bootstrap

    [6.0.100-1]
    - Update to .NET 6

    [6.0.0-0.7.rc2]
    - Update to .NET 6 RC2

    [6.0.0-0.6.28be3e9a006d90d8c6e87d4353b77882829df718]
    - Enable building on arm64
    - Related: RHBZ#1986017

    [6.0.0-0.5.28be3e9a006d90d8c6e87d4353b77882829df718]
    - Enable building on s390x
    - Related: RHBZ#1986017

    [6.0.0-0.4.28be3e9a006d90d8c6e87d4353b77882829df718]
    - Clean up tarball and add initial support for s390x
    - Related: RHBZ#1986017

    [6.0.0-0.3.28be3e9a006d90d8c6e87d4353b77882829df718]
    - Update to work-in-progress RC2 release

    [6.0.0-0.2.preview6]
    - Updated to build the latest source-build preview

    [6.0.0-0.1.preview6]
    - Initial package for .NET 6

    [5.0.204-1]
    - Update to .NET SDK 5.0.204 and Runtime 5.0.7

    [5.0.203-1]
    - Update to .NET SDK 5.0.203 and Runtime 5.0.6

    [5.0.202-1]
    - Update to .NET SDK 5.0.202 and Runtime 5.0.5

    [5.0.104-2]
    - Mark files under /etc/ as config(noreplace)
    - Add an rpm-inspect configuration file
    - Add an rpmlintrc file
    - Enable gating for release branches and ELN too

    [5.0.104-1]
    - Update to .NET SDK 5.0.104 and Runtime 5.0.4
    - Drop unneeded/upstreamed patches

    [5.0.103-2]
    - Add Fedora 35 RIDs

    [5.0.103-1]
    - Update to .NET SDK 5.0.103 and Runtime 5.0.3

    [5.0.102-2]
    - Disable bootstrap

    [5.0.100-2]
    - Update to .NET Core Runtime 5.0.0 and SDK 5.0.100 commit 9c4e5de

    [5.0.100-1]
    - Update to .NET Core Runtime 5.0.0 and SDK 5.0.100

    [5.0.100-0.4.20201202git337413b]
    - Update to latest 5.0 pre-GA commit

    [5.0.100-0.4.20201123gitdee899c]
    - Update to 5.0 pre-GA commit

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-8434.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41032");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:aspnetcore-runtime-7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:aspnetcore-targeting-pack-7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-apphost-pack-7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-hostfxr-7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-runtime-7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-sdk-7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-sdk-7.0-source-built-artifacts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-targeting-pack-7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dotnet-templates-7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netstandard-targeting-pack-2.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'aspnetcore-runtime-7.0-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'aspnetcore-targeting-pack-7.0-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-apphost-pack-7.0-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-host-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-hostfxr-7.0-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-runtime-7.0-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-sdk-7.0-7.0.100-0.5.rc2.0.1.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-sdk-7.0-source-built-artifacts-7.0.100-0.5.rc2.0.1.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-targeting-pack-7.0-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-templates-7.0-7.0.100-0.5.rc2.0.1.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netstandard-targeting-pack-2.1-7.0.100-0.5.rc2.0.1.el9_1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'aspnetcore-runtime-7.0-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'aspnetcore-targeting-pack-7.0-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-apphost-pack-7.0-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-host-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-hostfxr-7.0-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-runtime-7.0-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-sdk-7.0-7.0.100-0.5.rc2.0.1.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-sdk-7.0-source-built-artifacts-7.0.100-0.5.rc2.0.1.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-targeting-pack-7.0-7.0.0-0.5.rc2.0.1.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dotnet-templates-7.0-7.0.100-0.5.rc2.0.1.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'netstandard-targeting-pack-2.1-7.0.100-0.5.rc2.0.1.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aspnetcore-runtime-7.0 / aspnetcore-targeting-pack-7.0 / dotnet-apphost-pack-7.0 / etc');
}
