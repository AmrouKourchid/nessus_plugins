#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:3627.
##

include('compat.inc');

if (description)
{
  script_id(200568);
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
  script_xref(name:"RLSA", value:"2024:3627");

  script_name(english:"Rocky Linux 8 : kernel-rt (RLSA-2024:3627)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:3627 advisory.

    * kernel: Marvin vulnerability side-channel leakage in the RSA decryption operation (CVE-2023-6240)

    * kernel: Information disclosure in vhost/vhost.c:vhost_new_msg() (CVE-2024-0340)

    * kernel: untrusted VMM can trigger int80 syscall handling (CVE-2024-25744)

    * kernel: i2c: i801: Fix block process call transactions (CVE-2024-26593)

    * kernel: pvrusb2: fix use after free on context disconnection (CVE-2023-52445)

    * kernel: x86/fpu: Stop relying on userspace for info to fault in xsave buffer that cause loop forever
    (CVE-2024-26603)

    * kernel: use after free in i2c (CVE-2019-25162)

    * kernel: i2c: validate user data in compat ioctl (CVE-2021-46934)

    * kernel: media: dvbdev: Fix memory leak in dvb_media_device_free() (CVE-2020-36777)

    * kernel: usb: hub: Guard against accesses to uninitialized BOS descriptors (CVE-2023-52477)

    * kernel: mtd: require write permissions for locking and badblock ioctls (CVE-2021-47055)

    * kernel: net/smc: fix illegal rmb_desc access in SMC-D connection dump (CVE-2024-26615)

    * kernel: vt: fix memory overlapping when deleting chars in the buffer (CVE-2022-48627)

    * kernel: Integer Overflow in raid5_cache_count (CVE-2024-23307)

    * kernel: media: uvcvideo: out-of-bounds read in uvc_query_v4l2_menu() (CVE-2023-52565)

    * kernel: net: bridge: data races indata-races in br_handle_frame_finish() (CVE-2023-52578)

    * kernel: net: usb: smsc75xx: Fix uninit-value access in __smsc75xx_read_reg (CVE-2023-52528)

    * kernel: platform/x86: think-lmi: Fix reference leak (CVE-2023-52520)

    * kernel: RDMA/siw: Fix connection failure handling (CVE-2023-52513)

    * kernel: pid: take a reference when initializing `cad_pid` (CVE-2021-47118)

    * kernel: net/sched: act_ct: fix skb leak and crash on ooo frags (CVE-2023-52610)

    * kernel: netfilter: nf_tables: mark set as dead when unbinding anonymous set with timeout
    (CVE-2024-26643)

    * kernel: netfilter: nf_tables: disallow anonymous set with timeout flag (CVE-2024-26642)

    * kernel: i2c: i801: Don't generate an interrupt on bus reset (CVE-2021-47153)

    * kernel: xhci: handle isoc Babble and Buffer Overrun events properly (CVE-2024-26659)

    * kernel: hwmon: (coretemp) Fix out-of-bounds memory access (CVE-2024-26664)

    * kernel: wifi: mac80211: fix race condition on enabling fast-xmit (CVE-2024-26779)

    * kernel: RDMA/srpt: Support specifying the srpt_service_guid parameter (CVE-2024-26744)

    * kernel: RDMA/qedr: Fix qedr_create_user_qp error flow (CVE-2024-26743)

    * kernel: tty: tty_buffer: Fix the softlockup issue in flush_to_ldisc (CVE-2021-47185)

    * kernel: do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak (CVE-2024-26901)

    * kernel: RDMA/srpt: Do not register event handler until srpt device is fully setup (CVE-2024-26872)

    * kernel: usb: ulpi: Fix debugfs directory leak (CVE-2024-26919)

    * kernel: usb: xhci: Add error handling in xhci_map_urb_for_dma (CVE-2024-26964)

    * kernel: USB: core: Fix deadlock in usb_deauthorize_interface() (CVE-2024-26934)

    * kernel: USB: core: Fix deadlock in port disable sysfs attribute (CVE-2024-26933)

    * kernel: fs: sysfs: Fix reference leak in sysfs_break_active_protection() (CVE-2024-26993)

    * kernel: fat: fix uninitialized field in nostale filehandles (CVE-2024-26973)

    * kernel: USB: usb-storage: Prevent divide-by-0 error in isd200_ata_command (CVE-2024-27059)

    Bug Fix(es):

    * kernel-rt: update RT source tree to the latest Rocky Linux-8.10.z kernel (JIRA:Rocky Linux-34640)

    * kernel-rt: epoll_wait not reporting catching all events to application (JIRA:Rocky Linux-23022)

Tenable has extracted the preceding description block directly from the Rocky Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:3627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2263875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278431");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2019-25162', 'CVE-2020-36777', 'CVE-2021-46934', 'CVE-2021-47013', 'CVE-2021-47055', 'CVE-2021-47118', 'CVE-2021-47153', 'CVE-2021-47171', 'CVE-2021-47185', 'CVE-2022-48627', 'CVE-2023-6240', 'CVE-2023-52439', 'CVE-2023-52445', 'CVE-2023-52477', 'CVE-2023-52513', 'CVE-2023-52520', 'CVE-2023-52528', 'CVE-2023-52565', 'CVE-2023-52578', 'CVE-2023-52594', 'CVE-2023-52595', 'CVE-2023-52610', 'CVE-2024-0340', 'CVE-2024-23307', 'CVE-2024-25744', 'CVE-2024-26593', 'CVE-2024-26603', 'CVE-2024-26610', 'CVE-2024-26615', 'CVE-2024-26642', 'CVE-2024-26643', 'CVE-2024-26659', 'CVE-2024-26664', 'CVE-2024-26693', 'CVE-2024-26694', 'CVE-2024-26743', 'CVE-2024-26744', 'CVE-2024-26779', 'CVE-2024-26872', 'CVE-2024-26892', 'CVE-2024-26897', 'CVE-2024-26901', 'CVE-2024-26919', 'CVE-2024-26933', 'CVE-2024-26934', 'CVE-2024-26964', 'CVE-2024-26973', 'CVE-2024-26993', 'CVE-2024-27014', 'CVE-2024-27048', 'CVE-2024-27052', 'CVE-2024-27056', 'CVE-2024-27059');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RLSA-2024:3627');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'reference':'kernel-rt-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-core-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-core-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-debuginfo-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-kvm-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-extra-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debuginfo-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debuginfo-common-x86_64-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-kvm-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-extra-4.18.0-553.5.1.rt7.346.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
