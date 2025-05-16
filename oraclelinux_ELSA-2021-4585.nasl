#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-4585.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155617);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2021-42574");
  script_xref(name:"IAVA", value:"2021-A-0528");

  script_name(english:"Oracle Linux 8 : gcc-toolset-10-gcc (ELSA-2021-4585)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2021-4585 advisory.

    [10.3.1-1.2.0.1]
    - Fix Orabug 32423691- gcc10 SEGV for every test in sregress: ORA-7445_ksmplru_add_batchksm
      same bug as PR tree-optimization/100053:
      gcc11-pr100053.patch
    - Fix Orabug 31197798 (Profile data size way too big)
      same bug as PR gcov-profile/95348:
      gcc11-pr95348.patch
    - Introduce 'oracle_release' into .spec file. Echo it to gcc/DEV-PHASE.
    Reviewed by: TBD

    [10.3.1-1.2]
    - add -Wbidirectional patch (#2016244)

    [10.3.1-1.1]
    - bump NVR for rebuild (#1995192)

    [10.3.1-1]
    - update from Fedora gcc 10.3.1-1 (#1929382)
    - drop gcc10-pr97060.patch
    - use --enable-cet
    - ship gcc-accel-nvptx-none-lto-dump
    - backport PR96939 fixes

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-4585.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42574");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-gcc-gdb-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-libasan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-libatomic-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-liblsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-libtsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-toolset-10-libubsan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libasan6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'gcc-toolset-10-gcc-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-c++-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-gdb-plugin-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-gfortran-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-plugin-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libasan-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libatomic-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libitm-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-liblsan-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libstdc++-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libstdc++-docs-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libtsan-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libubsan-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan6-10.3.1-1.2.0.1.el8_5', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-c++-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-gdb-plugin-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-gfortran-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-plugin-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libasan-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libatomic-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libitm-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-liblsan-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libquadmath-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libstdc++-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libstdc++-docs-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libtsan-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libubsan-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan6-10.3.1-1.2.0.1.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-c++-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-gdb-plugin-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-gfortran-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-gcc-plugin-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libasan-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libatomic-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libitm-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-liblsan-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libquadmath-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libstdc++-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libstdc++-docs-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libtsan-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-toolset-10-libubsan-devel-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan6-10.3.1-1.2.0.1.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gcc-toolset-10-gcc / gcc-toolset-10-gcc-c++ / gcc-toolset-10-gcc-gdb-plugin / etc');
}
