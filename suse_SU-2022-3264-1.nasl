#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3264-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165201);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/14");

  script_cve_id(
    "CVE-2016-3695",
    "CVE-2020-27784",
    "CVE-2021-4155",
    "CVE-2021-4203",
    "CVE-2022-2588",
    "CVE-2022-2663",
    "CVE-2022-2905",
    "CVE-2022-2977",
    "CVE-2022-3028",
    "CVE-2022-20368",
    "CVE-2022-20369",
    "CVE-2022-26373",
    "CVE-2022-36879",
    "CVE-2022-39188",
    "CVE-2022-39190"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3264-1");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : kernel (SUSE-SU-2022:3264-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2022:3264-1 advisory.

  - The einj_error_inject function in drivers/acpi/apei/einj.c in the Linux kernel allows local users to
    simulate hardware errors and consequently cause a denial of service by leveraging failure to disable APEI
    error injection through EINJ when securelevel is set. (CVE-2016-3695)

  - A vulnerability was found in the Linux kernel, where accessing a deallocated instance in printer_ioctl()
    printer_ioctl() tries to access of a printer_dev instance. However, use-after-free arises because it had
    been freed by gprinter_free(). (CVE-2020-27784)

  - A data leak flaw was found in the way XFS_IOC_ALLOCSP IOCTL in the XFS filesystem allowed for size
    increase of files with unaligned size. A local attacker could use this flaw to leak data on the XFS
    filesystem otherwise not accessible to them. (CVE-2021-4155)

  - A use-after-free read flaw was found in sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and
    SO_PEERGROUPS race with listen() (and connect()) in the Linux kernel. In this flaw, an attacker with a
    user privileges may crash the system or leak internal kernel information. (CVE-2021-4203)

  - Product: AndroidVersions: Android kernelAndroid ID: A-224546354References: Upstream kernel
    (CVE-2022-20368)

  - In v4l2_m2m_querybuf of v4l2-mem2mem.c, there is a possible out of bounds write due to improper input
    validation. This could lead to local escalation of privilege with System execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-223375145References: Upstream kernel (CVE-2022-20369)

  - kernel: a use-after-free in cls_route filter implementation may lead to privilege escalation
    (CVE-2022-2588)

  - Non-transparent sharing of return predictor targets between contexts in some Intel(R) Processors may allow
    an authorized user to potentially enable information disclosure via local access. (CVE-2022-26373)

  - An issue was found in the Linux kernel in nf_conntrack_irc where the message handling can be confused and
    incorrectly matches the message. A firewall may be able to be bypassed when users are using unencrypted
    IRC with nf_conntrack_irc configured. (CVE-2022-2663)

  - An out-of-bounds memory read flaw was found in the Linux kernel's BPF subsystem in how a user calls the
    bpf_tail_call function with a key larger than the max_entries of the map. This flaw allows a local user to
    gain unauthorized access to data. (CVE-2022-2905)

  - A flaw was found in the Linux kernel implementation of proxied virtualized TPM devices. On a system where
    virtualized TPM devices are configured (this is not the default) a local attacker can create a use-after-
    free and create a situation where it may be possible to escalate privileges on the system. (CVE-2022-2977)

  - A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem)
    when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to
    potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read
    and copying it into a socket. (CVE-2022-3028)

  - An issue was discovered in the Linux kernel through 5.18.14. xfrm_expand_policies in
    net/xfrm/xfrm_policy.c can cause a refcount to be dropped twice. (CVE-2022-36879)

  - An issue was discovered in include/asm-generic/tlb.h in the Linux kernel before 5.19. Because of a race
    condition (unmap_mapping_range versus munmap), a device driver can free a page while it still has stale
    TLB entries. This only occurs in situations with VM_PFNMAP VMAs. (CVE-2022-39188)

  - An issue was discovered in net/netfilter/nf_tables_api.c in the Linux kernel before 5.19.6. A denial of
    service can occur upon binding to an already bound chain. (CVE-2022-39190)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1023051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203137");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-3695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4203");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20368");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20369");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26373");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39190");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-September/012229.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b554749");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4203");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2977");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_93-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'dlm-kmp-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'gfs2-kmp-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-64kb-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-64kb-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-64kb-devel-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-64kb-devel-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.93.1.150300.18.54.1', 'sp':'3', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.93.1.150300.18.54.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-extra-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-extra-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-livepatch-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-livepatch-5_3_18-150300_59_93-default-1-150300.7.3.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-extra-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-extra-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-zfcpdump-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-zfcpdump-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'ocfs2-kmp-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'cluster-md-kmp-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-ha-release-15.3', 'sles-release-15.3']},
    {'reference':'dlm-kmp-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-ha-release-15.3', 'sles-release-15.3']},
    {'reference':'gfs2-kmp-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-ha-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-64kb-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-64kb-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-64kb-devel-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-64kb-devel-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.93.1.150300.18.54.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.93.1.150300.18.54.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-default-livepatch-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-live-patching-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-live-patching-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-livepatch-5_3_18-150300_59_93-default-1-150300.7.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-live-patching-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-zfcpdump-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-zfcpdump-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ocfs2-kmp-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-ha-release-15.3', 'sles-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.93.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-legacy-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-default-extra-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-default-extra-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-preempt-extra-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'kernel-preempt-extra-5.3.18-150300.59.93.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
