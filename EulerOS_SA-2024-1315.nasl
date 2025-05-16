#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191985);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2022-48619",
    "CVE-2023-1829",
    "CVE-2023-6040",
    "CVE-2023-6121",
    "CVE-2023-6546",
    "CVE-2023-6606",
    "CVE-2023-6931",
    "CVE-2023-6932",
    "CVE-2023-7192",
    "CVE-2024-0340",
    "CVE-2024-0565",
    "CVE-2024-0584"
  );

  script_name(english:"EulerOS 2.0 SP10 : kernel (EulerOS-SA-2024-1315)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - An issue was discovered in drivers/input/input.c in the Linux kernel before 5.17.10. An attacker can cause
    a denial of service (panic) because input_set_capability mishandles the situation in which an event code
    falls outside of a bitmap. (CVE-2022-48619)

  - A use-after-free vulnerability in the Linux Kernel traffic control index filter (tcindex) can be exploited
    to achieve local privilege escalation. The tcindex_delete function which does not properly deactivate
    filters in case of a perfect hashes while deleting the underlying structure which can later lead to double
    freeing the structure. A local attacker user can use this vulnerability to elevate its privileges to root.
    We recommend upgrading past commit 8c710f75256bb3cf05ac7b1672c82b92c43f3d28. (CVE-2023-1829)

  - An out-of-bounds access vulnerability involving netfilter was reported and fixed as: f1082dd31fe4
    (netfilter: nf_tables: Reject tables of unsupported family); While creating a new netfilter table, lack of
    a safeguard against invalid nf_tables family (pf) values within `nf_tables_newtable` function enables an
    attacker to achieve out-of-bounds access. (CVE-2023-6040)

  - An out-of-bounds read vulnerability was found in the NVMe-oF/TCP subsystem in the Linux kernel. This issue
    may allow a remote attacker to send a crafted TCP packet, triggering a heap-based buffer overflow that
    results in kmalloc data being printed and potentially leaked to the kernel ring buffer (dmesg).
    (CVE-2023-6121)

  - A race condition was found in the GSM 0710 tty multiplexor in the Linux kernel. This issue occurs when two
    threads execute the GSMIOC_SETCONF ioctl on the same tty file descriptor with the gsm line discipline
    enabled, and can lead to a use-after-free problem on a struct gsm_dlci while restarting the gsm mux. This
    could allow a local unprivileged user to escalate their privileges on the system. (CVE-2023-6546)

  - An out-of-bounds read vulnerability was found in smbCalcSize in fs/smb/client/netmisc.c in the Linux
    Kernel. This issue could allow a local attacker to crash the system or leak internal kernel information.
    (CVE-2023-6606)

  - A heap out-of-bounds write vulnerability in the Linux kernel's Performance Events system component can be
    exploited to achieve local privilege escalation. A perf_event's read_size can overflow, leading to an heap
    out-of-bounds increment or write in perf_read_group(). We recommend upgrading past commit
    382c27f4ed28f803b1f1473ac2d8db0afc795a1b. (CVE-2023-6931)

  - A use-after-free vulnerability in the Linux kernel's ipv4: igmp component can be exploited to achieve
    local privilege escalation. A race condition can be exploited to cause a timer be mistakenly registered on
    a RCU read locked object which is freed by another thread. We recommend upgrading past commit
    e2b706c691905fe78468c361aaabc719d0a496f1. (CVE-2023-6932)

  - A memory leak problem was found in ctnetlink_create_conntrack in net/netfilter/nf_conntrack_netlink.c in
    the Linux Kernel. This issue may allow a local attacker with CAP_NET_ADMIN privileges to cause a denial of
    service (DoS) attack due to a refcount overflow. (CVE-2023-7192)

  - A vulnerability was found in vhost_new_msg in drivers/vhost/vhost.c in the Linux kernel, which does not
    properly initialize memory in messages passed between virtual guests and the host operating system in the
    vhost/vhost.c:vhost_new_msg() function. This issue can allow local privileged users to read some kernel
    memory contents when reading from the /dev/vhost-net device file. (CVE-2024-0340)

  - An out-of-bounds memory read flaw was found in receive_encrypted_standard in fs/smb/client/smb2ops.c in
    the SMB Client sub-component in the Linux Kernel. This issue occurs due to integer underflow on the memcpy
    length, leading to a denial of service. (CVE-2024-0565)

  - Rejected reason: Do not use this CVE as it is duplicate of CVE-2023-6932 (CVE-2024-0584)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1315
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08101cb7");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0565");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-6040");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/12");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.19.90-vhulk2211.3.0.h1689.eulerosv2r10",
  "kernel-abi-stablelists-4.19.90-vhulk2211.3.0.h1689.eulerosv2r10",
  "kernel-tools-4.19.90-vhulk2211.3.0.h1689.eulerosv2r10",
  "kernel-tools-libs-4.19.90-vhulk2211.3.0.h1689.eulerosv2r10",
  "python3-perf-4.19.90-vhulk2211.3.0.h1689.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
