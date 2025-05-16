#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# the CentOS Stream Build Service.
##

include('compat.inc');

if (description)
{
  script_id(215234);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id("CVE-2020-11023");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/13");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"CentOS 9 : gcc-11.5.0-5.el9");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update for cpp.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
gcc-11.5.0-5.el9 build changelog.

  - In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing <option>
    elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods
    (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.
    (CVE-2020-11023)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=74801");
  script_set_attribute(attribute:"solution", value:
"Update the CentOS 9 Stream cpp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cross-gcc-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cross-gcc-c++-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-gdb-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-plugin-annobin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libasan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgccjit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgccjit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgfortran-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgomp-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libitm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:liblsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:liblsan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libquadmath-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtsan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libubsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libubsan-static");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'CentOS 9.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'cpp-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-gcc-aarch64-11.5.0-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-gcc-c++-aarch64-11.5.0-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-offload-nvptx-11.5.0-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-annobin-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-static-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-static-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgccjit-devel-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-static-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-offload-nvptx-11.5.0-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-static-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-11.5.0-5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-11.5.0-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-static-11.5.0-5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-static-11.5.0-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-11.5.0-5.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-11.5.0-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-devel-11.5.0-5.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-devel-11.5.0-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-static-11.5.0-5.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-static-11.5.0-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-11.5.0-5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-11.5.0-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-static-11.5.0-5.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-static-11.5.0-5.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-static-11.5.0-5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cpp / cross-gcc-aarch64 / cross-gcc-c++-aarch64 / gcc / gcc-c++ / etc');
}
