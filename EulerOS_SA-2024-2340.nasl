#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206551);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/03");

  script_cve_id("CVE-2024-28085");

  script_name(english:"EulerOS Virtualization 2.12.0 : util-linux (EulerOS-SA-2024-2340)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the util-linux packages installed, the EulerOS Virtualization installation on the remote
host is affected by the following vulnerabilities :

    wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to
    be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are
    blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where
    this leads to account takeover.(CVE-2024-28085)

Tenable has extracted the preceding description block directly from the EulerOS Virtualization util-linux security
advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2340
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66a88b2a");
  script_set_attribute(attribute:"solution", value:
"Update the affected util-linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28085");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libfdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmartcols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:util-linux-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.12.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.12.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "libblkid-2.37.2-13.h22.eulerosv2r12",
  "libfdisk-2.37.2-13.h22.eulerosv2r12",
  "libmount-2.37.2-13.h22.eulerosv2r12",
  "libsmartcols-2.37.2-13.h22.eulerosv2r12",
  "libuuid-2.37.2-13.h22.eulerosv2r12",
  "util-linux-2.37.2-13.h22.eulerosv2r12",
  "util-linux-user-2.37.2-13.h22.eulerosv2r12"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "util-linux");
}
