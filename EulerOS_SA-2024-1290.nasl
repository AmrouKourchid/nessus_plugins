#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191889);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/12");

  script_cve_id("CVE-2022-48560", "CVE-2022-48565", "CVE-2022-48566");

  script_name(english:"EulerOS 2.0 SP8 : python2 (EulerOS-SA-2024-1290)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python2 packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - A use-after-free exists in Python through 3.9 via heappushpop in heapq. (CVE-2022-48560)

  - An XML External Entity (XXE) issue was discovered in Python through 3.9.1. The plistlib module no longer
    accepts entity declarations in XML plist files to avoid XML vulnerabilities. (CVE-2022-48565)

  - An issue was discovered in compare_digest in Lib/hmac.py in Python through 3.9.1. Constant-time-defeating
    optimisations were possible in the accumulator variable in hmac.compare_digest. (CVE-2022-48566)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1290
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f4e7f74");
  script_set_attribute(attribute:"solution", value:
"Update the affected python2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48565");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-unversioned-command");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-test");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

var flag = 0;

var pkgs = [
  "python-unversioned-command-2.7.15-10.h37.eulerosv2r8",
  "python2-2.7.15-10.h37.eulerosv2r8",
  "python2-devel-2.7.15-10.h37.eulerosv2r8",
  "python2-libs-2.7.15-10.h37.eulerosv2r8",
  "python2-test-2.7.15-10.h37.eulerosv2r8"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2");
}
