#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192339);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/21");

  script_cve_id("CVE-2023-4039");

  script_name(english:"EulerOS Virtualization 2.11.0 : gcc (EulerOS-SA-2024-1440)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the gcc packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - **DISPUTED**A failure in the -fstack-protector feature in GCC-based toolchains that target AArch64 allows
    an attacker to exploit an existing buffer overflow in dynamically-sized local variables in your
    application without this being detected. This stack-protector failure only applies to C99-style
    dynamically-sized local variables or those created using alloca(). The stack-protector operates as
    intended for statically-sized local variables. The default behavior when the stack-protector detects an
    overflow is to terminate your application, resulting in controlled loss of availability. An attacker who
    can exploit a buffer overflow without triggering the stack-protector might be able to change program flow
    control to cause an uncontrolled loss of availability or to go further and affect confidentiality or
    integrity. NOTE: The GCC project argues that this is a missed hardening bug and not a vulnerability by
    itself. (CVE-2023-4039)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1440
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ce50d55");
  script_set_attribute(attribute:"solution", value:
"Update the affected gcc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4039");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libstdc++");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.11.0");
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
if (uvp != "2.11.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.11.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "libasan-10.3.1-10.h18.eulerosv2r11",
  "libatomic-10.3.1-10.h18.eulerosv2r11",
  "libgcc-10.3.1-10.h18.eulerosv2r11",
  "libgfortran-10.3.1-10.h18.eulerosv2r11",
  "libgomp-10.3.1-10.h18.eulerosv2r11",
  "libobjc-10.3.1-10.h18.eulerosv2r11",
  "libquadmath-10.3.1-10.h18.eulerosv2r11",
  "libstdc++-10.3.1-10.h18.eulerosv2r11"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc");
}
