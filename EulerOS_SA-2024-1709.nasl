#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197252);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id(
    "CVE-2023-0494",
    "CVE-2023-1393",
    "CVE-2023-5367",
    "CVE-2023-5380",
    "CVE-2023-6377",
    "CVE-2023-6478"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.0 : xorg-x11-server (EulerOS-SA-2024-1709)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the xorg-x11-server packages installed, the EulerOS Virtualization installation on the
remote host is affected by the following vulnerabilities :

  - A vulnerability was found in X.Org. This issue occurs due to a dangling pointer in DeepCopyPointerClasses
    that can be exploited by ProcXkbSetDeviceInfo() and ProcXkbGetDeviceInfo() to read and write into freed
    memory. This can lead to local privilege elevation on systems where the X server runs privileged and
    remote code execution for ssh X forwarding sessions. (CVE-2023-0494)

  - A flaw was found in X.Org Server Overlay Window. A Use-After-Free may lead to local privilege escalation.
    If a client explicitly destroys the compositor overlay window (aka COW), the Xserver would leave a
    dangling pointer to that window in the CompScreen structure, which will trigger a use-after-free later.
    (CVE-2023-1393)

  - A out-of-bounds write flaw was found in the xorg-x11-server. This issue occurs due to an incorrect
    calculation of a buffer offset when copying data stored in the heap in the XIChangeDeviceProperty function
    in Xi/xiproperty.c and in RRChangeOutputProperty function in randr/rrproperty.c, allowing for possible
    escalation of privileges or denial of service. (CVE-2023-5367)

  - A use-after-free flaw was found in the xorg-x11-server. An X server crash may occur in a very specific and
    legacy configuration (a multi-screen setup with multiple protocol screens, also known as Zaphod mode) if
    the pointer is warped from within a window on one screen to the root window of the other screen and if the
    original window is destroyed followed by another window being destroyed. (CVE-2023-5380)

  - A flaw was found in xorg-server. Querying or changing XKB button actions such as moving from a touchpad to
    a mouse can result in out-of-bounds memory reads and writes. This may allow local privilege escalation or
    possible remote code execution in cases where X11 forwarding is involved. (CVE-2023-6377)

  - A flaw was found in xorg-server. A specially crafted request to RRChangeProviderProperty or
    RRChangeOutputProperty can trigger an integer overflow which may lead to a disclosure of sensitive
    information. (CVE-2023-6478)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1709
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d169b4ed");
  script_set_attribute(attribute:"solution", value:
"Update the affected xorg-x11-server packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6478");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-6377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:xorg-x11-server-Xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "xorg-x11-server-Xephyr-1.20.1-4.h17.eulerosv2r8",
  "xorg-x11-server-Xorg-1.20.1-4.h17.eulerosv2r8",
  "xorg-x11-server-Xvfb-1.20.1-4.h17.eulerosv2r8",
  "xorg-x11-server-Xwayland-1.20.1-4.h17.eulerosv2r8",
  "xorg-x11-server-common-1.20.1-4.h17.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server");
}
