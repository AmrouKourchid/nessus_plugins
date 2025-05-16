#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205962);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/21");

  script_cve_id("CVE-2024-3446", "CVE-2024-3447");

  script_name(english:"EulerOS Virtualization 2.11.1 : qemu (EulerOS-SA-2024-2176)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu package installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

    QEMU is a FAST! processor emulator using dynamic translation to achieve good emulation speed.QEMU has two
    operating modes: Full system emulation. In this mode, QEMU emulates a full system (for example a PC),
    including one or several processors and various peripherals. It can be used to launch different Operating
    Systems without rebooting the PC or to debug system code. User mode emulation. In this mode, QEMU can
    launch processes compiled for one CPU on another CPU. It can be used to launch the Wine Windows API
    emulator (https://www.winehq.org) or to ease cross-compilation and cross-debugging.You can refer to
    https://www.qemu.org for more infortmation.A heap based buffer overflow was found in the SDHCI device
    emulation of QEMU. The bug is triggered when both `s-data_count` and the size of `s-fifo_buffer` are
    set to 0x200, leading to an out-of-bound access. A malicious guest could use this flaw to crash the QEMU
    process on the host, resulting in a denial of service condition.(CVE-2024-3447
    )

    QEMU is a FAST! processor emulator using dynamic translation to achieve good emulation speed.QEMU has two
    operating modes: Full system emulation. In this mode, QEMU emulates a full system (for example a PC),
    including one or several processors and various peripherals. It can be used to launch different Operating
    Systems without rebooting the PC or to debug system code. User mode emulation. In this mode, QEMU can
    launch processes compiled for one CPU on another CPU. It can be used to launch the Wine Windows API
    emulator (https://www.winehq.org) or to ease cross-compilation and cross-debugging.You can refer to
    https://www.qemu.org for more infortmation.A double free vulnerability was found in QEMU virtio devices
    (virtio-gpu, virtio-serial-bus, virtio-crypto), where the mem_reentrancy_guard flag insufficiently
    protects against DMA reentrancy issues. This issue could allow a malicious privileged guest user to crash
    the QEMU process on the host, resulting in a denial of service or allow arbitrary code execution within
    the context of the QEMU process on the host.(CVE-2024-3446)

Tenable has extracted the preceding description block directly from the EulerOS Virtualization qemu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2176
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f96f0080");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3446");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.11.1");
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
if (uvp != "2.11.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.11.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "qemu-6.2.0-470"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
