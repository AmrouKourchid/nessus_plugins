#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178373);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2022-27672",
    "CVE-2023-0458",
    "CVE-2023-0459",
    "CVE-2023-2002",
    "CVE-2023-2124",
    "CVE-2023-2162",
    "CVE-2023-2176",
    "CVE-2023-2177",
    "CVE-2023-2248",
    "CVE-2023-2269",
    "CVE-2023-30456",
    "CVE-2023-31436"
  );

  script_name(english:"EulerOS 2.0 SP10 : kernel (EulerOS-SA-2023-2357)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - When SMT is enabled, certain AMD processors may speculatively execute instructions using a target from the
    sibling thread after an SMT mode switch potentially resulting in information disclosure. (CVE-2022-27672)

  - A speculative pointer dereference problem exists in the Linux Kernel on the do_prlimit() function. The
    resource argument value is controlled and is used in pointer arithmetic for the 'rlim' variable and can be
    used to leak the contents. We recommend upgrading past version 6.1.8 or commit
    739790605705ddcf18f21782b9c99ad7d53a8c11 (CVE-2023-0458)

  - Copy_from_user on 64-bit versions of the Linux kernel does not implement the __uaccess_begin_nospec
    allowing a user to bypass the 'access_ok' check and pass a kernel pointer to copy_from_user(). This would
    allow an attacker to leak information. We recommend upgrading beyond commit
    74e19ef0ff8061ef55957c3abd71614ef0f42f47 (CVE-2023-0459)

  - A vulnerability was found in the HCI sockets implementation due to a missing capability check in
    net/bluetooth/hci_sock.c in the Linux Kernel. This flaw allows an attacker to unauthorized execution of
    management commands, compromising the confidentiality, integrity, and availability of Bluetooth
    communication. (CVE-2023-2002)

  - An out-of-bounds memory access flaw was found in the Linux kernel's XFS file system in how a user restores
    an XFS image after failure (with a dirty log journal). This flaw allows a local user to crash or
    potentially escalate their privileges on the system. (CVE-2023-2124)

  - A use-after-free vulnerability was found in iscsi_sw_tcp_session_create in drivers/scsi/iscsi_tcp.c in
    SCSI sub-component in the Linux Kernel. In this flaw an attacker could leak kernel internal information.
    (CVE-2023-2162)

  - A vulnerability was found in compare_netdev_and_ip in drivers/infiniband/core/cma.c in RDMA in the Linux
    Kernel. The improper cleanup results in out-of-boundary read, where a local user can utilize this problem
    to crash the system or escalation of privilege. (CVE-2023-2176)

  - A null pointer dereference issue was found in the sctp network protocol in net/sctp/stream_sched.c in
    Linux Kernel. If stream_in allocation is failed, stream_out is freed which would further be accessed. A
    local user could use this flaw to crash the system or potentially cause a denial of service.
    (CVE-2023-2177)

  - Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority because it was
    the duplicate of CVE-2023-31436. (CVE-2023-2248)

  - A denial of service problem was found, due to a possible recursive locking scenario, resulting in a
    deadlock in table_clear in drivers/md/dm-ioctl.c in the Linux Kernel Device Mapper-Multipathing sub-
    component. (CVE-2023-2269)

  - An issue was discovered in arch/x86/kvm/vmx/nested.c in the Linux kernel before 6.2.8. nVMX on x86_64
    lacks consistency checks for CR0 and CR4. (CVE-2023-30456)

  - qfq_change_class in net/sched/sch_qfq.c in the Linux kernel before 6.2.13 allows an out-of-bounds write
    because lmax can exceed QFQ_MIN_LMAX. (CVE-2023-31436)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2357
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42efe9bf");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31436");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.18.0-147.5.2.19.h1305.eulerosv2r10",
  "kernel-abi-stablelists-4.18.0-147.5.2.19.h1305.eulerosv2r10",
  "kernel-tools-4.18.0-147.5.2.19.h1305.eulerosv2r10",
  "kernel-tools-libs-4.18.0-147.5.2.19.h1305.eulerosv2r10",
  "python3-perf-4.18.0-147.5.2.19.h1305.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
