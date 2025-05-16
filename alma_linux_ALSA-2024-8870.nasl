#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:8870.
##

include('compat.inc');

if (description)
{
  script_id(210445);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id(
    "CVE-2022-48773",
    "CVE-2022-48936",
    "CVE-2023-52492",
    "CVE-2024-24857",
    "CVE-2024-26851",
    "CVE-2024-26924",
    "CVE-2024-26976",
    "CVE-2024-27017",
    "CVE-2024-27062",
    "CVE-2024-35839",
    "CVE-2024-35898",
    "CVE-2024-35939",
    "CVE-2024-38540",
    "CVE-2024-38541",
    "CVE-2024-38586",
    "CVE-2024-38608",
    "CVE-2024-39503",
    "CVE-2024-40924",
    "CVE-2024-40961",
    "CVE-2024-40983",
    "CVE-2024-40984",
    "CVE-2024-41009",
    "CVE-2024-41042",
    "CVE-2024-41066",
    "CVE-2024-41092",
    "CVE-2024-41093",
    "CVE-2024-42070",
    "CVE-2024-42079",
    "CVE-2024-42244",
    "CVE-2024-42284",
    "CVE-2024-42292",
    "CVE-2024-42301",
    "CVE-2024-43854",
    "CVE-2024-43880",
    "CVE-2024-43889",
    "CVE-2024-43892",
    "CVE-2024-44935",
    "CVE-2024-44989",
    "CVE-2024-44990",
    "CVE-2024-45018",
    "CVE-2024-46826",
    "CVE-2024-47668"
  );
  script_xref(name:"ALSA", value:"2024:8870");
  script_xref(name:"IAVA", value:"2024-A-0487");
  script_xref(name:"RHSA", value:"2024:8870");

  script_name(english:"AlmaLinux 8 : kernel-rt (ALSA-2024:8870)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:8870 advisory.

    * kernel: net/bluetooth: race condition in conn_info_{min,max}_age_set() (CVE-2024-24857)
      * kernel: dmaengine: fix NULL pointer in channel unregistration function (CVE-2023-52492)
      * kernel: netfilter: nf_conntrack_h323: Add protection for bmp length out of range (CVE-2024-26851)
      * kernel: netfilter: nft_set_pipapo: do not free live element (CVE-2024-26924)
      * kernel: netfilter: nft_set_pipapo: walk over current view on netlink dump (CVE-2024-27017)
      * kernel: KVM: Always flush async #PF workqueue when vCPU is being destroyed (CVE-2024-26976)
      * kernel: nouveau: lock the client object tree. (CVE-2024-27062)
      * kernel: netfilter: bridge: replace physindev with physinif in nf_bridge_info (CVE-2024-35839)
      * kernel: netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get() (CVE-2024-35898)
      * kernel: dma-direct: Leak pages on dma_set_decrypted() failure (CVE-2024-35939)
      * kernel: net/mlx5e: Fix netif state handling (CVE-2024-38608)
      * kernel: r8169: Fix possible ring buffer corruption on fragmented Tx packets. (CVE-2024-38586)
      * kernel: of: module: add buffer overflow check in of_modalias() (CVE-2024-38541)
      * kernel: bnxt_re: avoid shift undefined behavior in bnxt_qplib_alloc_init_hwq (CVE-2024-38540)
      * kernel: netfilter: ipset: Fix race between namespace cleanup and gc in the list:set type
    (CVE-2024-39503)
      * kernel: drm/i915/dpt: Make DPT object unshrinkable (CVE-2024-40924)
      * kernel: ipv6: prevent possible NULL deref in fib6_nh_init() (CVE-2024-40961)
      * kernel: tipc: force a dst refcount before doing decryption (CVE-2024-40983)
      * kernel: ACPICA: Revert ACPICA: avoid Info: mapping multiple BARs. Your kernel is fine.
    (CVE-2024-40984)
      * kernel: xprtrdma: fix pointer derefs in error cases of rpcrdma_ep_create (CVE-2022-48773)
      * kernel: bpf: Fix overrunning reservations in ringbuf (CVE-2024-41009)
      * kernel: netfilter: nf_tables: prefer nft_chain_validate (CVE-2024-41042)
      * kernel: ibmvnic: Add tx check to prevent skb leak (CVE-2024-41066)
      * kernel: drm/i915/gt: Fix potential UAF by revoke of fence registers (CVE-2024-41092)
      * kernel: drm/amdgpu: avoid using null object of framebuffer (CVE-2024-41093)
      * kernel: netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers
    (CVE-2024-42070)
      * kernel: gfs2: Fix NULL pointer dereference in gfs2_log_flush (CVE-2024-42079)
      * kernel: USB: serial: mos7840: fix crash on resume (CVE-2024-42244)
      * kernel: tipc: Return non-zero value from tipc_udp_addr2str() on error (CVE-2024-42284)
      * kernel: kobject_uevent: Fix OOB access within zap_modalias_env() (CVE-2024-42292)
      * kernel: dev/parport: fix the array out-of-bounds risk (CVE-2024-42301)
      * kernel: block: initialize integrity buffer to zero before writing it to media (CVE-2024-43854)
      * kernel: mlxsw: spectrum_acl_erp: Fix object nesting warning (CVE-2024-43880)
      * kernel: gso: do not skip outer ip header in case of ipip and net_failover (CVE-2022-48936)
      * kernel: padata: Fix possible divide-by-0 panic in padata_mt_helper() (CVE-2024-43889)
      * kernel: memcg: protect concurrent access to mem_cgroup_idr (CVE-2024-43892)
      * kernel: sctp: Fix null-ptr-deref in reuseport_add_sock(). (CVE-2024-44935)
      * kernel: bonding: fix xfrm real_dev null pointer dereference (CVE-2024-44989)
      * kernel: bonding: fix null pointer deref in bond_ipsec_offload_ok (CVE-2024-44990)
      * kernel: netfilter: flowtable: initialise extack before use (CVE-2024-45018)
      * kernel: ELF: fix kernel.randomize_va_space double read (CVE-2024-46826)
      * kernel: lib/generic-radix-tree.c: Fix rare race in __genradix_ptr_alloc() (CVE-2024-47668)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-8870.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:8870");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 125, 190, 20, 200, 284, 362, 369, 393, 401, 402, 413, 416, 457, 476, 911, 99);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2022-48773', 'CVE-2022-48936', 'CVE-2023-52492', 'CVE-2024-24857', 'CVE-2024-26851', 'CVE-2024-26924', 'CVE-2024-26976', 'CVE-2024-27017', 'CVE-2024-27062', 'CVE-2024-35839', 'CVE-2024-35898', 'CVE-2024-35939', 'CVE-2024-38540', 'CVE-2024-38541', 'CVE-2024-38586', 'CVE-2024-38608', 'CVE-2024-39503', 'CVE-2024-40924', 'CVE-2024-40961', 'CVE-2024-40983', 'CVE-2024-40984', 'CVE-2024-41009', 'CVE-2024-41042', 'CVE-2024-41066', 'CVE-2024-41092', 'CVE-2024-41093', 'CVE-2024-42070', 'CVE-2024-42079', 'CVE-2024-42244', 'CVE-2024-42284', 'CVE-2024-42292', 'CVE-2024-42301', 'CVE-2024-43854', 'CVE-2024-43880', 'CVE-2024-43889', 'CVE-2024-43892', 'CVE-2024-44935', 'CVE-2024-44989', 'CVE-2024-44990', 'CVE-2024-45018', 'CVE-2024-46826', 'CVE-2024-47668');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2024:8870');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'kernel-rt-4.18.0-553.27.1.rt7.368.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-core-4.18.0-553.27.1.rt7.368.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-debug-4.18.0-553.27.1.rt7.368.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-debug-core-4.18.0-553.27.1.rt7.368.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-debug-devel-4.18.0-553.27.1.rt7.368.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-debug-modules-4.18.0-553.27.1.rt7.368.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-debug-modules-extra-4.18.0-553.27.1.rt7.368.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-devel-4.18.0-553.27.1.rt7.368.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-modules-4.18.0-553.27.1.rt7.368.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-modules-extra-4.18.0-553.27.1.rt7.368.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-core / kernel-rt-debug / kernel-rt-debug-core / etc');
}
