#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:3618.
##

include('compat.inc');

if (description)
{
  script_id(200115);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/09");

  script_cve_id(
    "CVE-2019-25162",
    "CVE-2020-36777",
    "CVE-2021-46934",
    "CVE-2021-47013",
    "CVE-2021-47055",
    "CVE-2021-47118",
    "CVE-2021-47153",
    "CVE-2021-47171",
    "CVE-2021-47185",
    "CVE-2022-48627",
    "CVE-2022-48669",
    "CVE-2023-6240",
    "CVE-2023-52439",
    "CVE-2023-52445",
    "CVE-2023-52477",
    "CVE-2023-52513",
    "CVE-2023-52520",
    "CVE-2023-52528",
    "CVE-2023-52565",
    "CVE-2023-52578",
    "CVE-2023-52594",
    "CVE-2023-52595",
    "CVE-2023-52598",
    "CVE-2023-52606",
    "CVE-2023-52607",
    "CVE-2023-52610",
    "CVE-2024-0340",
    "CVE-2024-23307",
    "CVE-2024-25744",
    "CVE-2024-26593",
    "CVE-2024-26603",
    "CVE-2024-26610",
    "CVE-2024-26615",
    "CVE-2024-26642",
    "CVE-2024-26643",
    "CVE-2024-26659",
    "CVE-2024-26664",
    "CVE-2024-26693",
    "CVE-2024-26694",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26779",
    "CVE-2024-26872",
    "CVE-2024-26892",
    "CVE-2024-26897",
    "CVE-2024-26901",
    "CVE-2024-26919",
    "CVE-2024-26933",
    "CVE-2024-26934",
    "CVE-2024-26964",
    "CVE-2024-26973",
    "CVE-2024-26993",
    "CVE-2024-27014",
    "CVE-2024-27048",
    "CVE-2024-27052",
    "CVE-2024-27056",
    "CVE-2024-27059"
  );
  script_xref(name:"ALSA", value:"2024:3618");

  script_name(english:"AlmaLinux 8 : kernel update (Medium) (ALSA-2024:3618)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:3618 advisory.

    * kernel: Marvin vulnerability side-channel leakage in the RSA decryption
    operation (CVE-2023-6240)
    * kernel: Information disclosure in vhost/vhost.c:vhost_new_msg()
    (CVE-2024-0340)
    * kernel: untrusted VMM can trigger int80 syscall handling (CVE-2024-25744)
    * kernel: i2c: i801: Fix block process call transactions (CVE-2024-26593)
    * kernel: pvrusb2: fix use after free on context disconnection (CVE-2023-52445)
    * kernel: x86/fpu: Stop relying on userspace for info to fault in xsave buffer
    that cause loop forever (CVE-2024-26603)
    * kernel: use after free in i2c (CVE-2019-25162)
    * kernel: i2c: validate user data in compat ioctl (CVE-2021-46934)
    * kernel: media: dvbdev: Fix memory leak in dvb_media_device_free()
    (CVE-2020-36777)
    * kernel: usb: hub: Guard against accesses to uninitialized BOS descriptors
    (CVE-2023-52477)
    * kernel: mtd: require write permissions for locking and badblock ioctls
    (CVE-2021-47055)
    * kernel: net/smc: fix illegal rmb_desc access in SMC-D connection dump
    (CVE-2024-26615)
    * kernel: vt: fix memory overlapping when deleting chars in the buffer
    (CVE-2022-48627)
    * kernel: Integer Overflow in raid5_cache_count (CVE-2024-23307)
    * kernel: media: uvcvideo: out-of-bounds read in uvc_query_v4l2_menu()
    (CVE-2023-52565)
    * kernel: net: bridge: data races indata-races in br_handle_frame_finish()
    (CVE-2023-52578)
    * kernel: net: usb: smsc75xx: Fix uninit-value access in __smsc75xx_read_reg
    (CVE-2023-52528)
    * kernel: platform/x86: think-lmi: Fix reference leak (CVE-2023-52520)
    * kernel: RDMA/siw: Fix connection failure handling (CVE-2023-52513)
    * kernel: pid: take a reference when initializing `cad_pid` (CVE-2021-47118)
    * kernel: net/sched: act_ct: fix skb leak and crash on ooo frags
    (CVE-2023-52610)
    * kernel: netfilter: nf_tables: mark set as dead when unbinding anonymous set
    with timeout (CVE-2024-26643)
    * kernel: netfilter: nf_tables: disallow anonymous set with timeout flag
    (CVE-2024-26642)
    * kernel: i2c: i801: Don't generate an interrupt on bus reset
    (CVE-2021-47153)
    * kernel: xhci: handle isoc Babble and Buffer Overrun events properly
    (CVE-2024-26659)
    * kernel: hwmon: (coretemp) Fix out-of-bounds memory access (CVE-2024-26664)
    * kernel: wifi: mac80211: fix race condition on enabling fast-xmit
    (CVE-2024-26779)
    * kernel: RDMA/srpt: Support specifying the srpt_service_guid parameter
    (CVE-2024-26744)
    * kernel: RDMA/qedr: Fix qedr_create_user_qp error flow (CVE-2024-26743)
    * kernel: tty: tty_buffer: Fix the softlockup issue in flush_to_ldisc
    (CVE-2021-47185)
    * kernel: do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak
    (CVE-2024-26901)
    * kernel: RDMA/srpt: Do not register event handler until srpt device is fully
    setup (CVE-2024-26872)
    * kernel: usb: ulpi: Fix debugfs directory leak (CVE-2024-26919)
    * kernel: usb: xhci: Add error handling in xhci_map_urb_for_dma (CVE-2024-26964)
    * kernel: USB: core: Fix deadlock in usb_deauthorize_interface()
    (CVE-2024-26934)
    * kernel: USB: core: Fix deadlock in port disable sysfs attribute
    (CVE-2024-26933)
    * kernel: fs: sysfs: Fix reference leak in sysfs_break_active_protection()
    (CVE-2024-26993)
    * kernel: fat: fix uninitialized field in nostale filehandles (CVE-2024-26973)
    * kernel: USB: usb-storage: Prevent divide-by-0 error in isd200_ata_command
    (CVE-2024-27059)
    * kernel: net:emac/emac-mac: Fix a use after free in emac_mac_tx_buf_send (CVE-2021-47013)
    * kernel: net: usb: fix memory leak in smsc75xx_bind (CVE-2021-47171)
    * kernel: powerpc/pseries: Fix potential memleak in papr_get_attr() (CVE-2022-48669)
    * kernel: uio: Fix use-after-free in uio_open (CVE-2023-52439)
    * kernel: wifi: ath9k: Fix potential array-index-out-of-bounds read in ath9k_htc_txstatus()
    (CVE-2023-52594)
    * kernel: wifi: rt2x00: restart beacon queue when hardware reset (CVE-2023-52595)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-3618.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26934");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-25744");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(1050, 119, 121, 125, 1260, 190, 20, 200, 203, 252, 362, 395, 401, 402, 415, 416, 459, 476, 680, 703, 835, 99);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-perf");
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
  var cve_list = make_list('CVE-2019-25162', 'CVE-2020-36777', 'CVE-2021-46934', 'CVE-2021-47013', 'CVE-2021-47055', 'CVE-2021-47118', 'CVE-2021-47153', 'CVE-2021-47171', 'CVE-2021-47185', 'CVE-2022-48627', 'CVE-2022-48669', 'CVE-2023-6240', 'CVE-2023-52439', 'CVE-2023-52445', 'CVE-2023-52477', 'CVE-2023-52513', 'CVE-2023-52520', 'CVE-2023-52528', 'CVE-2023-52565', 'CVE-2023-52578', 'CVE-2023-52594', 'CVE-2023-52595', 'CVE-2023-52598', 'CVE-2023-52606', 'CVE-2023-52607', 'CVE-2023-52610', 'CVE-2024-0340', 'CVE-2024-23307', 'CVE-2024-25744', 'CVE-2024-26593', 'CVE-2024-26603', 'CVE-2024-26610', 'CVE-2024-26615', 'CVE-2024-26642', 'CVE-2024-26643', 'CVE-2024-26659', 'CVE-2024-26664', 'CVE-2024-26693', 'CVE-2024-26694', 'CVE-2024-26743', 'CVE-2024-26744', 'CVE-2024-26779', 'CVE-2024-26872', 'CVE-2024-26892', 'CVE-2024-26897', 'CVE-2024-26901', 'CVE-2024-26919', 'CVE-2024-26933', 'CVE-2024-26934', 'CVE-2024-26964', 'CVE-2024-26973', 'CVE-2024-26993', 'CVE-2024-27014', 'CVE-2024-27048', 'CVE-2024-27052', 'CVE-2024-27056', 'CVE-2024-27059');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2024:3618');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'bpftool-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-abi-stablelists-4.18.0-553.5.1.el8_10', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-core-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-core-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-devel-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-modules-extra-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / kernel-core / etc');
}
