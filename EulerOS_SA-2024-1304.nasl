#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191884);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/12");

  script_cve_id(
    "CVE-2023-0494",
    "CVE-2023-1393",
    "CVE-2023-6377",
    "CVE-2023-6478"
  );

  script_name(english:"EulerOS 2.0 SP8 : tigervnc (EulerOS-SA-2024-1304)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the tigervnc packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - A vulnerability was found in X.Org. This issue occurs due to a dangling pointer in DeepCopyPointerClasses
    that can be exploited by ProcXkbSetDeviceInfo() and ProcXkbGetDeviceInfo() to read and write into freed
    memory. This can lead to local privilege elevation on systems where the X server runs privileged and
    remote code execution for ssh X forwarding sessions. (CVE-2023-0494)

  - A flaw was found in X.Org Server Overlay Window. A Use-After-Free may lead to local privilege escalation.
    If a client explicitly destroys the compositor overlay window (aka COW), the Xserver would leave a
    dangling pointer to that window in the CompScreen structure, which will trigger a use-after-free later.
    (CVE-2023-1393)

  - A flaw was found in xorg-server. Querying or changing XKB button actions such as moving from a touchpad to
    a mouse can result in out-of-bounds memory reads and writes. This may allow local privilege escalation or
    possible remote code execution in cases where X11 forwarding is involved. (CVE-2023-6377)

  - A flaw was found in xorg-server. A specially crafted request to RRChangeProviderProperty or
    RRChangeOutputProperty can trigger an integer overflow which may lead to a disclosure of sensitive
    information. (CVE-2023-6478)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1304
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f2d1d49");
  script_set_attribute(attribute:"solution", value:
"Update the affected tigervnc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6478");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-6377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tigervnc-server-minimal");
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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "tigervnc-1.9.0-3.h8.eulerosv2r8",
  "tigervnc-icons-1.9.0-3.h8.eulerosv2r8",
  "tigervnc-license-1.9.0-3.h8.eulerosv2r8",
  "tigervnc-server-1.9.0-3.h8.eulerosv2r8",
  "tigervnc-server-minimal-1.9.0-3.h8.eulerosv2r8"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tigervnc");
}
