#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3182-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(179350);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id(
    "CVE-2023-2985",
    "CVE-2023-3117",
    "CVE-2023-3390",
    "CVE-2023-3609",
    "CVE-2023-3611",
    "CVE-2023-3812",
    "CVE-2023-20593",
    "CVE-2023-31248",
    "CVE-2023-35001"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3182-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2023:3182-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:3182-1 advisory.

  - An issue in Zen 2 CPUs, under specific microarchitectural circumstances, may allow an attacker to
    potentially access sensitive information. (CVE-2023-20593)

  - A use after free flaw was found in hfsplus_put_super in fs/hfsplus/super.c in the Linux Kernel. This flaw
    could allow a local user to cause a denial of service problem. (CVE-2023-2985)

  - ** REJECT ** DO NOT USE THIS CVE RECORD. ConsultIDs: CVE-2023-3390. Reason: This record is a duplicate of
    CVE-2023-3390. Notes: All CVE users should reference CVE-2023-3390 instead of this record. All references
    and descriptions in this record have been removed to prevent accidental usage. (CVE-2023-3117)

  - Linux Kernel nftables Use-After-Free Local Privilege Escalation Vulnerability; `nft_chain_lookup_byid()`
    failed to check whether a chain was active and CAP_NET_ADMIN is in any user or network namespace
    (CVE-2023-31248)

  - A use-after-free vulnerability was found in the Linux kernel's netfilter subsystem in
    net/netfilter/nf_tables_api.c. Mishandled error handling with NFT_MSG_NEWRULE makes it possible to use a
    dangling pointer in the same transaction causing a use-after-free vulnerability. This flaw allows a local
    attacker with user access to cause a privilege escalation issue. We recommend upgrading past commit
    1240eb93f0616b21c675416516ff3d74798fdc97. (CVE-2023-3390)

  - Linux Kernel nftables Out-Of-Bounds Read/Write Vulnerability; nft_byteorder poorly handled vm register
    contents when CAP_NET_ADMIN is in any user or network namespace (CVE-2023-35001)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_u32 component can be exploited to
    achieve local privilege escalation. If tcf_change_indev() fails, u32_set_parms() will immediately return
    an error after incrementing or decrementing the reference counter in tcf_bind_filter(). If an attacker can
    control the reference counter and set it to zero, they can cause the reference to be freed, leading to a
    use-after-free vulnerability. We recommend upgrading past commit 04c55383fa5689357bcdd2c8036725a55ed632bc.
    (CVE-2023-3609)

  - An out-of-bounds write vulnerability in the Linux kernel's net/sched: sch_qfq component can be exploited
    to achieve local privilege escalation. The qfq_change_agg() function in net/sched/sch_qfq.c allows an out-
    of-bounds write because lmax is updated according to packet sizes without bounds checks. We recommend
    upgrading past commit 3e337087c3b5805fe0b8a46ba622a962880b5d64. (CVE-2023-3611)

  - An out-of-bounds memory access flaw was found in the Linux kernel's TUN/TAP device driver functionality in
    how a user generates a malicious (too big) networking packet when napi frags is enabled. This flaw allows
    a local user to crash or potentially escalate their privileges on the system. (CVE-2023-3812)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1150305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213110");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213705");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-August/030784.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-20593");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2985");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3117");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-31248");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3390");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3812");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3812");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/04");

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

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-5.14.21-150400.14.60.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.60.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.60.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.60.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-devel-azure-5.14.21-150400.14.60.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-source-azure-5.14.21-150400.14.60.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.60.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.60.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.60.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'kernel-azure-5.14.21-150400.14.60.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.60.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.60.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'kernel-devel-azure-5.14.21-150400.14.60.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'kernel-source-azure-5.14.21-150400.14.60.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.60.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.60.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150400.14.60.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150400.14.60.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-azure-5.14.21-150400.14.60.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-azure-5.14.21-150400.14.60.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-azure-5.14.21-150400.14.60.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-azure-5.14.21-150400.14.60.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.60.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-5.14.21-150400.14.60.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.60.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-devel-5.14.21-150400.14.60.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-extra-5.14.21-150400.14.60.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-extra-5.14.21-150400.14.60.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150400.14.60.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150400.14.60.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-optional-5.14.21-150400.14.60.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-azure-optional-5.14.21-150400.14.60.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-devel-azure-5.14.21-150400.14.60.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-source-azure-5.14.21-150400.14.60.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.60.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-azure-5.14.21-150400.14.60.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kselftests-kmp-azure-5.14.21-150400.14.60.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kselftests-kmp-azure-5.14.21-150400.14.60.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150400.14.60.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150400.14.60.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150400.14.60.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150400.14.60.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
