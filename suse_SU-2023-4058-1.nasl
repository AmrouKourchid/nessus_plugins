#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:4058-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(183008);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/13");

  script_cve_id(
    "CVE-2023-1192",
    "CVE-2023-1206",
    "CVE-2023-1859",
    "CVE-2023-2177",
    "CVE-2023-4155",
    "CVE-2023-4389",
    "CVE-2023-4622",
    "CVE-2023-4623",
    "CVE-2023-4881",
    "CVE-2023-4921",
    "CVE-2023-5345",
    "CVE-2023-37453",
    "CVE-2023-39192",
    "CVE-2023-39193",
    "CVE-2023-39194",
    "CVE-2023-40283",
    "CVE-2023-42753",
    "CVE-2023-42754"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:4058-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2023:4058-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:4058-1 advisory.

  - A hash collision flaw was found in the IPv6 connection lookup table in the Linux kernel's IPv6
    functionality when a user makes a new kind of SYN flood attack. A user located in the local network or
    with a high bandwidth connection can increase the CPU usage of the server that accepts IPV6 connections up
    to 95%. (CVE-2023-1206)

  - A use-after-free flaw was found in xen_9pfs_front_removet in net/9p/trans_xen.c in Xen transport for 9pfs
    in the Linux Kernel. This flaw could allow a local attacker to crash the system due to a race problem,
    possibly leading to a kernel information leak. (CVE-2023-1859)

  - A null pointer dereference issue was found in the sctp network protocol in net/sctp/stream_sched.c in
    Linux Kernel. If stream_in allocation is failed, stream_out is freed which would further be accessed. A
    local user could use this flaw to crash the system or potentially cause a denial of service.
    (CVE-2023-2177)

  - An issue was discovered in the USB subsystem in the Linux kernel through 6.4.2. There is an out-of-bounds
    and crash in read_descriptors in drivers/usb/core/sysfs.c. (CVE-2023-37453)

  - A flaw was found in the Netfilter subsystem in the Linux kernel. The xt_u32 module did not validate the
    fields in the xt_u32 structure. This flaw allows a local privileged attacker to trigger an out-of-bounds
    read by setting the size fields with a value beyond the array boundaries, leading to a crash or
    information disclosure. (CVE-2023-39192)

  - A flaw was found in the Netfilter subsystem in the Linux kernel. The sctp_mt_check did not validate the
    flag_count field. This flaw allows a local privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds
    read, leading to a crash or information disclosure. (CVE-2023-39193)

  - A flaw was found in the XFRM subsystem in the Linux kernel. The specific flaw exists within the processing
    of state filters, which can result in a read past the end of an allocated buffer. This flaw allows a local
    privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds read, potentially leading to an
    information disclosure. (CVE-2023-39194)

  - An issue was discovered in l2cap_sock_release in net/bluetooth/l2cap_sock.c in the Linux kernel before
    6.4.10. There is a use-after-free because the children of an sk are mishandled. (CVE-2023-40283)

  - A flaw was found in KVM AMD Secure Encrypted Virtualization (SEV) in the Linux kernel. A KVM guest using
    SEV-ES or SEV-SNP with multiple vCPUs can trigger a double fetch race condition vulnerability and invoke
    the `VMGEXIT` handler recursively. If an attacker manages to call the handler multiple times, they can
    trigger a stack overflow and cause a denial of service or potentially guest-to-host escape in kernel
    configurations without stack guard pages (`CONFIG_VMAP_STACK`). (CVE-2023-4155)

  - An array indexing vulnerability was found in the netfilter subsystem of the Linux kernel. A missing macro
    could lead to a miscalculation of the `h->nets` array offset, providing attackers with the primitive to
    arbitrarily increment/decrement a memory buffer out-of-bound. This issue may allow a local user to crash
    the system or potentially escalate their privileges on the system. (CVE-2023-42753)

  - A NULL pointer dereference flaw was found in the Linux kernel ipv4 stack. The socket buffer (skb) was
    assumed to be associated with a device before calling __ip_options_compile, which is not always the case
    if the skb is re-routed by ipvs. This issue may allow a local user with CAP_NET_ADMIN privileges to crash
    the system. (CVE-2023-42754)

  - A flaw was found in btrfs_get_root_ref in fs/btrfs/disk-io.c in the btrfs filesystem in the Linux Kernel
    due to a double decrement of the reference count. This issue may allow a local attacker with user
    privilege to crash the system or may lead to leaked internal kernel information. (CVE-2023-4389)

  - A use-after-free vulnerability in the Linux kernel's af_unix component can be exploited to achieve local
    privilege escalation. The unix_stream_sendpage() function tries to add data to the last skb in the peer's
    recv queue without locking the queue. Thus there is a race where unix_stream_sendpage() could access an
    skb locklessly that is being released by garbage collection, resulting in use-after-free. We recommend
    upgrading past commit 790c2f9d15b594350ae9bca7b236f2b1859de02c. (CVE-2023-4622)

  - A use-after-free vulnerability in the Linux kernel's net/sched: sch_hfsc (HFSC qdisc traffic control)
    component can be exploited to achieve local privilege escalation. If a class with a link-sharing curve
    (i.e. with the HFSC_FSC flag set) has a parent without a link-sharing curve, then init_vf() will call
    vttree_insert() on the parent, but vttree_remove() will be skipped in update_vf(). This leaves a dangling
    pointer that can cause a use-after-free. We recommend upgrading past commit
    b3d26c5702c7d6c45456326e56d2ccf3f103e60f. (CVE-2023-4623)

  - A use-after-free vulnerability in the Linux kernel's net/sched: sch_qfq component can be exploited to
    achieve local privilege escalation. When the plug qdisc is used as a class of the qfq qdisc, sending
    network packets triggers use-after-free in qfq_dequeue() due to the incorrect .peek handler of sch_plug
    and lack of error checking in agg_dequeue(). We recommend upgrading past commit
    8fc134fee27f2263988ae38920bc03da416b03d8. (CVE-2023-4921)

  - A use-after-free vulnerability in the Linux kernel's fs/smb/client component can be exploited to achieve
    local privilege escalation. In case of an error in smb3_fs_context_parse_param, ctx->password was freed
    but the field was not set to NULL which could lead to double free. We recommend upgrading past commit
    e6e43b8aa7cd3c3af686caf0c2e11819a886d705. (CVE-2023-5345)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215124");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215957");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-October/016647.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?beee0ddf");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2177");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-37453");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39193");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39194");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-40283");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-42753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-42754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5345");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5345");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-5.14.21-150500.33.20.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.20.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.20.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.20.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.20.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.20.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.20.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.20.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.20.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.20.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.20.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.20.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.20.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.20.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.20.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.20.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150500.33.20.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-azure-5.14.21-150500.33.20.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-azure-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-azure-5.14.21-150500.33.20.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-azure-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.20.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.20.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-extra-5.14.21-150500.33.20.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-extra-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150500.33.20.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-optional-5.14.21-150500.33.20.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-optional-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-vdso-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.20.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.20.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.20.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-azure-5.14.21-150500.33.20.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-azure-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150500.33.20.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150500.33.20.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150500.33.20.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-azure / dlm-kmp-azure / gfs2-kmp-azure / etc');
}
