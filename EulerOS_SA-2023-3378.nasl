#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188736);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2023-1206",
    "CVE-2023-3772",
    "CVE-2023-4004",
    "CVE-2023-4128",
    "CVE-2023-4132",
    "CVE-2023-4133",
    "CVE-2023-4147",
    "CVE-2023-4194",
    "CVE-2023-4273",
    "CVE-2023-4387",
    "CVE-2023-4459",
    "CVE-2023-25775"
  );

  script_name(english:"EulerOS Virtualization 2.11.0 : kernel (EulerOS-SA-2023-3378)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - A hash collision flaw was found in the IPv6 connection lookup table in the Linux kernel's IPv6
    functionality when a user makes a new kind of SYN flood attack. A user located in the local network or
    with a high bandwidth connection can increase the CPU usage of the server that accepts IPV6 connections up
    to 95%. (CVE-2023-1206)

  - Improper access control in the Intel(R) Ethernet Controller RDMA driver for linux before version 1.9.30
    may allow an unauthenticated user to potentially enable escalation of privilege via network access.
    (CVE-2023-25775)

  - A flaw was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem). This issue
    may allow a malicious user with CAP_NET_ADMIN privileges to directly dereference a NULL pointer in
    xfrm_update_ae_params(), leading to a possible kernel crash and denial of service. (CVE-2023-3772)

  - A use-after-free flaw was found in the Linux kernel's netfilter in the way a user triggers the
    nft_pipapo_remove function with the element, without a NFT_SET_EXT_KEY_END. This issue could allow a local
    user to crash the system or potentially escalate their privileges on the system. (CVE-2023-4004)

  - A use-after-free vulnerability was found in the siano smsusb module in the Linux kernel. The bug occurs
    during device initialization when the siano device is plugged in. This flaw allows a local user to crash
    the system, causing a denial of service condition. (CVE-2023-4132)

  - A use-after-free vulnerability was found in the cxgb4 driver in the Linux kernel. The bug occurs when the
    cxgb4 device is detaching due to a possible rearming of the flower_stats_timer from the work queue. This
    flaw allows a local user to crash the system, causing a denial of service condition. (CVE-2023-4133)

  - A use-after-free flaw was found in the Linux kernel's Netfilter functionality when adding a rule with
    NFTA_RULE_CHAIN_ID. This flaw allows a local user to crash or escalate their privileges on the system.
    (CVE-2023-4147)

  - A flaw was found in the Linux kernel's TUN/TAP functionality. This issue could allow a local user to
    bypass network filters and gain unauthorized access to some resources. The original patches fixing
    CVE-2023-1076 are incorrect or incomplete. The problem is that the following upstream commits -
    a096ccca6e50 ('tun: tun_chr_open(): correctly initialize socket uid'), - 66b2c338adce ('tap: tap_open():
    correctly initialize socket uid'), pass 'inode->i_uid' to sock_init_data_uid() as the last parameter and
    that turns out to not be accurate. (CVE-2023-4194)

  - A flaw was found in the exFAT driver of the Linux kernel. The vulnerability exists in the implementation
    of the file name reconstruction function, which is responsible for reading file name entries from a
    directory index and merging file name parts belonging to one file into a single long file name. Since the
    file name characters are copied into a stack variable, a local privileged attacker could use this flaw to
    overflow the kernel stack. (CVE-2023-4273)

  - A use-after-free flaw was found in vmxnet3_rq_alloc_rx_buf in drivers/net/vmxnet3/vmxnet3_drv.c in
    VMware's vmxnet3 ethernet NIC driver in the Linux Kernel. This issue could allow a local attacker to crash
    the system due to a double-free while cleaning up vmxnet3_rq_cleanup_all, which could also lead to a
    kernel information leak problem. (CVE-2023-4387)

  - A NULL pointer dereference flaw was found in vmxnet3_rq_cleanup in drivers/net/vmxnet3/vmxnet3_drv.c in
    the networking sub-component in vmxnet3 in the Linux Kernel. This issue may allow a local attacker with
    normal user privilege to cause a denial of service due to a missing sanity check during cleanup.
    (CVE-2023-4459)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3378
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?879cffb4");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25775");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
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
  "bpftool-5.10.0-60.18.0.50.h1002.eulerosv2r11",
  "kernel-5.10.0-60.18.0.50.h1002.eulerosv2r11",
  "kernel-abi-stablelists-5.10.0-60.18.0.50.h1002.eulerosv2r11",
  "kernel-tools-5.10.0-60.18.0.50.h1002.eulerosv2r11",
  "kernel-tools-libs-5.10.0-60.18.0.50.h1002.eulerosv2r11",
  "python3-perf-5.10.0-60.18.0.50.h1002.eulerosv2r11"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
