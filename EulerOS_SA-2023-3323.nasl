#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188661);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id("CVE-2023-3341");

  script_name(english:"EulerOS 2.0 SP9 : bind (EulerOS-SA-2023-3323)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bind packages installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

  - The code that processes control channel messages sent to `named` calls certain functions recursively
    during packet parsing. Recursion depth is only limited by the maximum accepted packet size; depending on
    the environment, this may cause the packet-parsing code to run out of available stack memory, causing
    `named` to terminate unexpectedly. Since each incoming control channel message is fully parsed before its
    contents are authenticated, exploiting this flaw does not require the attacker to hold a valid RNDC key;
    only network access to the control channel's configured TCP port is necessary. This issue affects BIND 9
    versions 9.2.0 through 9.16.43, 9.18.0 through 9.18.18, 9.19.0 through 9.19.16, 9.9.3-S1 through
    9.16.43-S1, and 9.18.0-S1 through 9.18.18-S1. (CVE-2023-3341)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3323
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b85fc5e");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3341");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "bind-9.11.4-17.h20.eulerosv2r9",
  "bind-chroot-9.11.4-17.h20.eulerosv2r9",
  "bind-export-libs-9.11.4-17.h20.eulerosv2r9",
  "bind-libs-9.11.4-17.h20.eulerosv2r9",
  "bind-libs-lite-9.11.4-17.h20.eulerosv2r9",
  "bind-pkcs11-9.11.4-17.h20.eulerosv2r9",
  "bind-utils-9.11.4-17.h20.eulerosv2r9",
  "python3-bind-9.11.4-17.h20.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
