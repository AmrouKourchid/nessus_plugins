#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214417);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id(
    "CVE-2024-32039",
    "CVE-2024-32040",
    "CVE-2024-32041",
    "CVE-2024-32459",
    "CVE-2024-32659"
  );

  script_name(english:"EulerOS 2.0 SP8 : freerdp (EulerOS-SA-2025-1120)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the freerdp packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients and servers that
    use a version of FreeRDP prior to 3.5.0 or 2.11.6 are vulnerable to out-of-bounds read. Versions 3.5.0 and
    2.11.6 patch the issue. No known workarounds are available.(CVE-2024-32459)

    FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients prior to version
    3.5.1 are vulnerable to out-of-bounds read if `((nWidth == 0) and (nHeight == 0))`. Version 3.5.1 contains
    a patch for the issue. No known workarounds are available.(CVE-2024-32659)

    FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients using a version of
    FreeRDP prior to 3.5.0 or 2.11.6 are vulnerable to integer overflow and out-of-bounds write. Versions
    3.5.0 and 2.11.6 patch the issue. As a workaround, do not use `/gfx` options (e.g. deactivate with
    `/bpp:32` or `/rfx` as it is on by default).(CVE-2024-32039)

    FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients that use a version
    of FreeRDP prior to 3.5.0 or 2.11.6 and have connections to servers using the `NSC` codec are vulnerable
    to integer underflow. Versions 3.5.0 and 2.11.6 patch the issue. As a workaround, do not use the NSC codec
    (e.g. use `-nsc`).(CVE-2024-32040)

    FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients that use a version
    of FreeRDP prior to 3.5.0 or 2.11.6 are vulnerable to out-of-bounds read. Versions 3.5.0 and 2.11.6 patch
    the issue. As a workaround, deactivate `/gfx` (on by default, set `/bpp` or `/rfx` options
    instead.(CVE-2024-32041)

Tenable has extracted the preceding description block directly from the EulerOS freerdp security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1120
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b909bb9b");
  script_set_attribute(attribute:"solution", value:
"Update the affected freerdp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32659");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwinpr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "freerdp-2.0.0-44.rc3.h18.eulerosv2r8",
  "freerdp-libs-2.0.0-44.rc3.h18.eulerosv2r8",
  "libwinpr-2.0.0-44.rc3.h18.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp");
}
