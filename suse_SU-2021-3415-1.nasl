#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3415-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154133);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/13");

  script_cve_id(
    "CVE-2020-3702",
    "CVE-2020-12770",
    "CVE-2021-3653",
    "CVE-2021-3656",
    "CVE-2021-3669",
    "CVE-2021-3732",
    "CVE-2021-3739",
    "CVE-2021-3743",
    "CVE-2021-3744",
    "CVE-2021-3752",
    "CVE-2021-3753",
    "CVE-2021-3759",
    "CVE-2021-3764",
    "CVE-2021-34556",
    "CVE-2021-35477",
    "CVE-2021-38160",
    "CVE-2021-38198",
    "CVE-2021-40490"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3415-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2021:3415-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:3415-1 advisory.

  - An issue was discovered in the Linux kernel through 5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka CID-83c6f2390040. (CVE-2020-12770)

  - u'Specifically timed and handcrafted traffic can cause internal errors in a WLAN device that lead to
    improper layer 2 Wi-Fi encryption with a consequent possibility of information disclosure over the air for
    a discrete set of traffic' in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon
    Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon
    Wearables, Snapdragon Wired Infrastructure and Networking in APQ8053, IPQ4019, IPQ8064, MSM8909W,
    MSM8996AU, QCA9531, QCN5502, QCS405, SDX20, SM6150, SM7150 (CVE-2020-3702)

  - In the Linux kernel through 5.13.7, an unprivileged BPF program can obtain sensitive information from
    kernel memory via a Speculative Store Bypass side-channel attack because the protection mechanism neglects
    the possibility of uninitialized memory locations on the BPF stack. (CVE-2021-34556)

  - In the Linux kernel through 5.13.7, an unprivileged BPF program can obtain sensitive information from
    kernel memory via a Speculative Store Bypass side-channel attack because a certain preempting store
    operation does not necessarily occur before a store operation that has an attacker-controlled value.
    (CVE-2021-35477)

  - A flaw was found in the KVM's AMD code for supporting SVM nested virtualization. The flaw occurs when
    processing the VMCB (virtual machine control block) provided by the L1 guest to spawn/handle a nested
    guest (L2). Due to improper validation of the int_ctl field, this issue could allow a malicious L1 to
    enable AVIC support (Advanced Virtual Interrupt Controller) for the L2 guest. As a result, the L2 guest
    would be allowed to read/write physical pages of the host, resulting in a crash of the entire system, leak
    of sensitive data or potential guest-to-host escape. This flaw affects Linux kernel versions prior to
    5.14-rc7. (CVE-2021-3653)

  - A flaw was found in the KVM's AMD code for supporting SVM nested virtualization. The flaw occurs when
    processing the VMCB (virtual machine control block) provided by the L1 guest to spawn/handle a nested
    guest (L2). Due to improper validation of the virt_ext field, this issue could allow a malicious L1 to
    disable both VMLOAD/VMSAVE intercepts and VLS (Virtual VMLOAD/VMSAVE) for the L2 guest. As a result, the
    L2 guest would be allowed to read/write physical pages of the host, resulting in a crash of the entire
    system, leak of sensitive data or potential guest-to-host escape. (CVE-2021-3656)

  - A flaw was found in the Linux kernel. Measuring usage of the shared memory does not scale with large
    shared memory segment counts which could lead to resource exhaustion and DoS. (CVE-2021-3669)

  - A flaw was found in the Linux kernel's OverlayFS subsystem in the way the user mounts the TmpFS filesystem
    with OverlayFS. This flaw allows a local user to gain access to hidden files that should not be
    accessible. (CVE-2021-3732)

  - A NULL pointer dereference flaw was found in the btrfs_rm_device function in fs/btrfs/volumes.c in the
    Linux Kernel, where triggering the bug requires CAP_SYS_ADMIN'. This flaw allows a local attacker to
    crash the system or leak kernel internal information. The highest threat from this vulnerability is to
    system availability. (CVE-2021-3739)

  - An out-of-bounds (OOB) memory read flaw was found in the Qualcomm IPC router protocol in the Linux kernel.
    A missing sanity check allows a local attacker to gain access to out-of-bounds memory, leading to a system
    crash or a leak of internal kernel information. The highest threat from this vulnerability is to system
    availability. (CVE-2021-3743)

  - A memory leak flaw was found in the Linux kernel in the ccp_run_aes_gcm_cmd() function in
    drivers/crypto/ccp/ccp-ops.c, which allows attackers to cause a denial of service (memory consumption).
    This vulnerability is similar with the older CVE-2019-18808. (CVE-2021-3744)

  - A use-after-free flaw was found in the Linux kernel's Bluetooth subsystem in the way user calls connect to
    the socket and disconnect simultaneously due to a race condition. This flaw allows a user to crash the
    system or escalate their privileges. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-3752)

  - A race problem was seen in the vt_k_ioctl in drivers/tty/vt/vt_ioctl.c in the Linux kernel, which may
    cause an out of bounds read in vt as the write access to vc_mode is not protected by lock-in vt_ioctl
    (KDSETMDE). The highest threat from this vulnerability is to data confidentiality. (CVE-2021-3753)

  - A memory overflow vulnerability was found in the Linux kernel's ipc functionality of the memcg subsystem,
    in the way a user calls the semget function multiple times, creating semaphores. This flaw allows a local
    user to starve the resources, causing a denial of service. The highest threat from this vulnerability is
    to system availability. (CVE-2021-3759)

  - A memory leak flaw was found in the Linux kernel's ccp_run_aes_gcm_cmd() function that allows an attacker
    to cause a denial of service. The vulnerability is similar to the older CVE-2019-18808. The highest threat
    from this vulnerability is to system availability. (CVE-2021-3764)

  - ** DISPUTED ** In drivers/char/virtio_console.c in the Linux kernel before 5.13.4, data corruption or loss
    can be triggered by an untrusted device that supplies a buf->len value exceeding the buffer size. NOTE:
    the vendor indicates that the cited data corruption is not a vulnerability in any existing use case; the
    length validation was added solely for robustness in the face of anomalous host OS behavior.
    (CVE-2021-38160)

  - arch/x86/kvm/mmu/paging_tmpl.h in the Linux kernel before 5.12.11 incorrectly computes the access
    permissions of a shadow page, leading to a missing guest protection page fault. (CVE-2021-38198)

  - A race condition was discovered in ext4_write_inline_data_end in fs/ext4/inline.c in the ext4 subsystem in
    the Linux kernel through 5.13.13. (CVE-2021-40490)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/859220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1124431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1127650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1135481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1148868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1170774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189225");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12770");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-34556");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-35477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-40490");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-October/009591.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f420fb0");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3752");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3656");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.3.18-57.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-rt-release-15.3']},
    {'reference':'dlm-kmp-rt-5.3.18-57.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-rt-release-15.3']},
    {'reference':'gfs2-kmp-rt-5.3.18-57.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-rt-release-15.3']},
    {'reference':'kernel-devel-rt-5.3.18-57.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-rt-release-15.3']},
    {'reference':'kernel-rt-5.3.18-57.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-rt-release-15.3']},
    {'reference':'kernel-rt-devel-5.3.18-57.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-rt-release-15.3']},
    {'reference':'kernel-rt_debug-devel-5.3.18-57.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-rt-release-15.3']},
    {'reference':'kernel-source-rt-5.3.18-57.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-rt-release-15.3']},
    {'reference':'kernel-syms-rt-5.3.18-57.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-rt-release-15.3']},
    {'reference':'ocfs2-kmp-rt-5.3.18-57.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-rt-release-15.3']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
