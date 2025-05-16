#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:4352.
##

include('compat.inc');

if (description)
{
  script_id(202069);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id(
    "CVE-2020-26555",
    "CVE-2021-46909",
    "CVE-2021-46972",
    "CVE-2021-47069",
    "CVE-2021-47073",
    "CVE-2021-47236",
    "CVE-2021-47310",
    "CVE-2021-47311",
    "CVE-2021-47353",
    "CVE-2021-47356",
    "CVE-2021-47456",
    "CVE-2021-47495",
    "CVE-2023-5090",
    "CVE-2023-52464",
    "CVE-2023-52560",
    "CVE-2023-52615",
    "CVE-2023-52626",
    "CVE-2023-52667",
    "CVE-2023-52700",
    "CVE-2023-52703",
    "CVE-2023-52781",
    "CVE-2023-52813",
    "CVE-2023-52835",
    "CVE-2023-52877",
    "CVE-2023-52878",
    "CVE-2023-52881",
    "CVE-2024-26583",
    "CVE-2024-26584",
    "CVE-2024-26585",
    "CVE-2024-26656",
    "CVE-2024-26675",
    "CVE-2024-26735",
    "CVE-2024-26759",
    "CVE-2024-26801",
    "CVE-2024-26804",
    "CVE-2024-26826",
    "CVE-2024-26859",
    "CVE-2024-26906",
    "CVE-2024-26907",
    "CVE-2024-26974",
    "CVE-2024-26982",
    "CVE-2024-27397",
    "CVE-2024-27410",
    "CVE-2024-35789",
    "CVE-2024-35835",
    "CVE-2024-35838",
    "CVE-2024-35845",
    "CVE-2024-35852",
    "CVE-2024-35853",
    "CVE-2024-35854",
    "CVE-2024-35855",
    "CVE-2024-35888",
    "CVE-2024-35890",
    "CVE-2024-35958",
    "CVE-2024-35959",
    "CVE-2024-35960",
    "CVE-2024-36004",
    "CVE-2024-36007"
  );
  script_xref(name:"ALSA", value:"2024:4352");

  script_name(english:"AlmaLinux 8 : kernel-rt (ALSA-2024:4352)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:4352 advisory.

    * kernel: tls (CVE-2024-26585,CVE-2024-26584, CVE-2024-26583
    * kernel-rt: kernel: PCI interrupt mapping cause oops [almalinux-8] (CVE-2021-46909)
    * kernel: ipc/mqueue, msg, sem: avoid relying on a stack reference past its expiry (CVE-2021-47069)
    * kernel: hwrng: core - Fix page fault dead lock on mmap-ed hwrng (CVE-2023-52615)
    * kernel-rt: kernel: drm/amdgpu: use-after-free vulnerability (CVE-2024-26656)
    * kernel: Bluetooth: Avoid potential use-after-free in hci_error_reset CVE-2024-26801)
    * kernel: Squashfs: check the inode number is not the invalid value of zero  (CVE-2024-26982)
    * kernel: netfilter: nf_tables: use timestamp to check for set element timeout (CVE-2024-27397)
    * kernel: wifi: mac80211: (CVE-2024-35789, CVE-2024-35838, CVE-2024-35845)
    * kernel: wifi: nl80211: reject iftype change with mesh ID change (CVE-2024-27410)
    * kernel: perf/core: Bail out early if the request AUX area is out of bound (CVE-2023-52835)
    * kernel:TCP-spoofed ghost ACKs and leak initial sequence number (CVE-2023-52881)
    * kernel: Bluetooth BR/EDR PIN Pairing procedure is vulnerable to an impersonation attack (CVE-2020-26555)
    * kernel: ovl: fix leaked dentry (CVE-2021-46972)
    * kernel: platform/x86: dell-smbios-wmi: Fix oops on rmmod dell_smbios (CVE-2021-47073)
    * kernel: mm/damon/vaddr-test: memory leak in damon_do_test_apply_three_regions() (CVE-2023-52560)
    * kernel: ppp_async: limit MRU to 64K (CVE-2024-26675)
    * kernel: mm/swap: fix race when skipping swapcache (CVE-2024-26759)
    * kernel: RDMA/mlx5: Fix fortify source warning while accessing Eth segment (CVE-2024-26907)
    * kernel: x86/mm: Disallow vsyscall page read for copy_from_kernel_nofault() (CVE-2024-26906)
    * kernel: net: ip_tunnel: prevent perpetual headroom growth (CVE-2024-26804)
    * kernel: net/usb: kalmia: avoid printing uninitialized value on error path (CVE-2023-52703)
    * kernel: KVM: SVM: improper check in svm_set_x2apic_msr_interception allows direct access to host x2apic
    msrs (CVE-2023-5090)
    * kernel: EDAC/thunderx: Incorrect buffer size in drivers/edac/thunderx_edac.c (CVE-2023-52464)
    * kernel: ipv6: sr: fix possible use-after-free and null-ptr-deref (CVE-2024-26735)
    * kernel: mptcp: fix data re-injection from stale subflow (CVE-2024-26826)
    * kernel: net/bnx2x: Prevent access to a freed page in page_pool (CVE-2024-26859)
    * kernel: crypto: (CVE-2024-26974, CVE-2023-52813)
    * kernel: can: (CVE-2023-52878, CVE-2021-47456)
    * kernel: usb: (CVE-2023-52781, CVE-2023-52877)
    * kernel: net/mlx5e: fix a potential double-free in fs_any_create_groups (CVE-2023-52667)
    * kernel: usbnet: sanity check for maxpacket (CVE-2021-47495)
    * kernel: gro: fix ownership transfer (CVE-2024-35890)
    * kernel: erspan: make sure erspan_base_hdr is present in skb->head (CVE-2024-35888)
    * kernel: tipc: fix kernel warning when sending SYN message (CVE-2023-52700)
    * kernel: net/mlx5/mlxsw: (CVE-2024-35960, CVE-2024-36007, CVE-2024-35855)
    * kernel: net/mlx5e: (CVE-2024-35959, CVE-2023-52626, CVE-2024-35835)
    * kernel: mlxsw: (CVE-2024-35854, CVE-2024-35853, CVE-2024-35852)
    * kernel: net: (CVE-2024-35958, CVE-2021-47311, CVE-2021-47236, CVE-2021-47310)
    * kernel: i40e: Do not use WQ_MEM_RECLAIM flag for workqueue (CVE-2024-36004)
    * kernel: mISDN: fix possible use-after-free in HFC_cleanup() (CVE-2021-47356)
    * kernel: udf: Fix NULL pointer dereference in udf_symlink function (CVE-2021-47353)

    Bug Fix(es):

    * kernel-rt: update RT source tree to the latest AlmaLinux-8.10.z kernel (JIRA:AlmaLinux-40882)
    * [almalinux8.9][cxgb4]BUG: using smp_processor_id() in preemptible [00000000] code: ethtool/54735
    (JIRA:AlmaLinux-8779)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-4352.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26555");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-35855");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 20, 362, 391, 393, 400, 401, 402, 416, 476, 755, 805, 833, 99);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-kvm");
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
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2020-26555', 'CVE-2021-46909', 'CVE-2021-46972', 'CVE-2021-47069', 'CVE-2021-47073', 'CVE-2021-47236', 'CVE-2021-47310', 'CVE-2021-47311', 'CVE-2021-47353', 'CVE-2021-47356', 'CVE-2021-47456', 'CVE-2021-47495', 'CVE-2023-5090', 'CVE-2023-52464', 'CVE-2023-52560', 'CVE-2023-52615', 'CVE-2023-52626', 'CVE-2023-52667', 'CVE-2023-52700', 'CVE-2023-52703', 'CVE-2023-52781', 'CVE-2023-52813', 'CVE-2023-52835', 'CVE-2023-52877', 'CVE-2023-52878', 'CVE-2023-52881', 'CVE-2024-26583', 'CVE-2024-26584', 'CVE-2024-26585', 'CVE-2024-26656', 'CVE-2024-26675', 'CVE-2024-26735', 'CVE-2024-26759', 'CVE-2024-26801', 'CVE-2024-26804', 'CVE-2024-26826', 'CVE-2024-26859', 'CVE-2024-26906', 'CVE-2024-26907', 'CVE-2024-26974', 'CVE-2024-26982', 'CVE-2024-27397', 'CVE-2024-27410', 'CVE-2024-35789', 'CVE-2024-35835', 'CVE-2024-35838', 'CVE-2024-35845', 'CVE-2024-35852', 'CVE-2024-35853', 'CVE-2024-35854', 'CVE-2024-35855', 'CVE-2024-35888', 'CVE-2024-35890', 'CVE-2024-35958', 'CVE-2024-35959', 'CVE-2024-35960', 'CVE-2024-36004', 'CVE-2024-36007');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2024:4352');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'kernel-rt-4.18.0-553.8.1.rt7.349.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-core-4.18.0-553.8.1.rt7.349.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-4.18.0-553.8.1.rt7.349.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-core-4.18.0-553.8.1.rt7.349.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-4.18.0-553.8.1.rt7.349.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-kvm-4.18.0-553.8.1.rt7.349.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-4.18.0-553.8.1.rt7.349.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-extra-4.18.0-553.8.1.rt7.349.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-4.18.0-553.8.1.rt7.349.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-kvm-4.18.0-553.8.1.rt7.349.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-4.18.0-553.8.1.rt7.349.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-extra-4.18.0-553.8.1.rt7.349.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
