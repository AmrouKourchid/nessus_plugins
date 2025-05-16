#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:1959.
##

include('compat.inc');

if (description)
{
  script_id(193955);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/26");

  script_cve_id(
    "CVE-2023-40546",
    "CVE-2023-40547",
    "CVE-2023-40548",
    "CVE-2023-40549",
    "CVE-2023-40550",
    "CVE-2023-40551"
  );
  script_xref(name:"RHSA", value:"2024:1959");

  script_name(english:"CentOS 7 : shim (RHSA-2024:1959)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2024:1959 advisory.

  - A flaw was found in Shim when an error happened while creating a new ESL variable. If Shim fails to create
    the new variable, it tries to print an error message to the user; however, the number of parameters used
    by the logging function doesn't match the format string used by it, leading to a crash under certain
    circumstances. (CVE-2023-40546)

  - A remote code execution vulnerability was found in Shim. The Shim boot support trusts attacker-controlled
    values when parsing an HTTP response. This flaw allows an attacker to craft a specific malicious HTTP
    request, leading to a completely controlled out-of-bounds write primitive and complete system compromise.
    This flaw is only exploitable during the early boot phase, an attacker needs to perform a Man-in-the-
    Middle or compromise the boot server to be able to exploit this vulnerability successfully.
    (CVE-2023-40547)

  - A buffer overflow was found in Shim in the 32-bit system. The overflow happens due to an addition
    operation involving a user-controlled value parsed from the PE binary being used by Shim. This value is
    further used for memory allocation operations, leading to a heap-based buffer overflow. This flaw causes
    memory corruption and can lead to a crash or data integrity issues during the boot phase. (CVE-2023-40548)

  - An out-of-bounds read flaw was found in Shim due to the lack of proper boundary verification during the
    load of a PE binary. This flaw allows an attacker to load a crafted PE binary, triggering the issue and
    crashing Shim, resulting in a denial of service. (CVE-2023-40549)

  - An out-of-bounds read flaw was found in Shim when it tried to validate the SBAT information. This issue
    may expose sensitive data during the system's boot phase. (CVE-2023-40550)

  - A flaw was found in the MZ binary format in Shim. An out-of-bounds read may occur, leading to a crash or
    possible exposure of sensitive data during the system's boot phase. (CVE-2023-40551)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:1959");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mokutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:shim-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:shim-unsigned-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:shim-unsigned-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:shim-x64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'mokutil-15.8-1.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'shim-ia32-15.8-1.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'shim-unsigned-ia32-15.8-3.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'shim-unsigned-x64-15.8-3.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'shim-x64-15.8-1.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mokutil / shim-ia32 / shim-unsigned-ia32 / etc');
}
