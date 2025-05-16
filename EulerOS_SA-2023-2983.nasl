#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188959);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/04");

  script_cve_id(
    "CVE-2020-36694",
    "CVE-2023-0458",
    "CVE-2023-0459",
    "CVE-2023-1075",
    "CVE-2023-2002",
    "CVE-2023-2124",
    "CVE-2023-2162",
    "CVE-2023-2177",
    "CVE-2023-2248",
    "CVE-2023-2269",
    "CVE-2023-3141",
    "CVE-2023-3159",
    "CVE-2023-3161",
    "CVE-2023-3268",
    "CVE-2023-3327",
    "CVE-2023-31084",
    "CVE-2023-31436",
    "CVE-2023-32233",
    "CVE-2023-34256",
    "CVE-2023-35788",
    "CVE-2023-35823",
    "CVE-2023-35824"
  );

  script_name(english:"EulerOS Virtualization 2.9.0 : kernel (EulerOS-SA-2023-2983)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - An issue was discovered in netfilter in the Linux kernel before 5.10. There can be a use-after-free in the
    packet processing context, because the per-CPU sequence count is mishandled during concurrent iptables
    rules replacement. This could be exploited with the CAP_NET_ADMIN capability in an unprivileged namespace.
    NOTE: cc00bca was reverted in 5.12. (CVE-2020-36694)

  - A speculative pointer dereference problem exists in the Linux Kernel on the do_prlimit() function. The
    resource argument value is controlled and is used in pointer arithmetic for the 'rlim' variable and can be
    used to leak the contents. We recommend upgrading past version 6.1.8 or commit
    739790605705ddcf18f21782b9c99ad7d53a8c11 (CVE-2023-0458)

  - Copy_from_user on 64-bit versions of the Linux kernel does not implement the __uaccess_begin_nospec
    allowing a user to bypass the 'access_ok' check and pass a kernel pointer to copy_from_user(). This would
    allow an attacker to leak information. We recommend upgrading beyond commit
    74e19ef0ff8061ef55957c3abd71614ef0f42f47 (CVE-2023-0459)

  - A flaw was found in the Linux Kernel. The tls_is_tx_ready() incorrectly checks for list emptiness,
    potentially accessing a type confused entry to the list_head, leaking the last byte of the confused field
    that overlaps with rec->tx_ready. (CVE-2023-1075)

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

  - A null pointer dereference issue was found in the sctp network protocol in net/sctp/stream_sched.c in
    Linux Kernel. If stream_in allocation is failed, stream_out is freed which would further be accessed. A
    local user could use this flaw to crash the system or potentially cause a denial of service.
    (CVE-2023-2177)

  - Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority because it was
    the duplicate of CVE-2023-31436. (CVE-2023-2248)

  - A denial of service problem was found, due to a possible recursive locking scenario, resulting in a
    deadlock in table_clear in drivers/md/dm-ioctl.c in the Linux Kernel Device Mapper-Multipathing sub-
    component. (CVE-2023-2269)

  - An issue was discovered in drivers/media/dvb-core/dvb_frontend.c in the Linux kernel 6.2. There is a
    blocking operation when a task is in !TASK_RUNNING. In dvb_frontend_get_event, wait_event_interruptible is
    called; the condition is dvb_frontend_test_event(fepriv,events). In dvb_frontend_test_event,
    down(&fepriv->sem) is called. However, wait_event_interruptible would put the process to sleep, and
    down(&fepriv->sem) may block the process. (CVE-2023-31084)

  - A use-after-free flaw was found in r592_remove in drivers/memstick/host/r592.c in media access in the
    Linux Kernel. This flaw allows a local attacker to crash the system at device disconnect, possibly leading
    to a kernel information leak. (CVE-2023-3141)

  - qfq_change_class in net/sched/sch_qfq.c in the Linux kernel before 6.2.13 allows an out-of-bounds write
    because lmax can exceed QFQ_MIN_LMAX. (CVE-2023-31436)

  - A use after free issue was discovered in driver/firewire in outbound_phy_packet_callback in the Linux
    Kernel. In this flaw a local attacker with special privilege may cause a use after free problem when
    queue_event() fails. (CVE-2023-3159)

  - A flaw was found in the Framebuffer Console (fbcon) in the Linux Kernel. When providing font->width and
    font->height greater than 32 to fbcon_set_font, since there are no checks in place, a shift-out-of-bounds
    occurs leading to undefined behavior and possible denial of service. (CVE-2023-3161)

  - In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests
    can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users
    can obtain root privileges. This occurs because anonymous sets are mishandled. (CVE-2023-32233)

  - An out of bounds (OOB) memory access flaw was found in the Linux kernel in relay_file_read_start_pos in
    kernel/relay.c in the relayfs. This flaw could allow a local attacker to crash the system or leak kernel
    internal information. (CVE-2023-3268)

  - Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2023-35823. Reason: This candidate is a
    reservation duplicate of CVE-2023-35823. Notes: All CVE users should reference CVE-2023-35823 instead of
    this candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2023-3327)

  - An issue was discovered in the Linux kernel before 6.3.3. There is an out-of-bounds read in crc16 in
    lib/crc16.c when called from fs/ext4/super.c because ext4_group_desc_csum does not properly check an
    offset. NOTE: this is disputed by third parties because the kernel is not intended to defend against
    attackers with the stated 'When modifying the block device while it is mounted by the filesystem' access.
    (CVE-2023-34256)

  - An issue was discovered in fl_set_geneve_opt in net/sched/cls_flower.c in the Linux kernel before 6.3.7.
    It allows an out-of-bounds write in the flower classifier code via TCA_FLOWER_KEY_ENC_OPTS_GENEVE packets.
    This may result in denial of service or privilege escalation. (CVE-2023-35788)

  - An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in saa7134_finidev in
    drivers/media/pci/saa7134/saa7134-core.c. (CVE-2023-35823)

  - An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in dm1105_remove in
    drivers/media/pci/dm1105/dm1105.c. (CVE-2023-35824)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2983
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8c89fa5");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
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
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.18.0-147.5.1.6.h1071.eulerosv2r9",
  "kernel-tools-4.18.0-147.5.1.6.h1071.eulerosv2r9",
  "kernel-tools-libs-4.18.0-147.5.1.6.h1071.eulerosv2r9",
  "python3-perf-4.18.0-147.5.1.6.h1071.eulerosv2r9"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
