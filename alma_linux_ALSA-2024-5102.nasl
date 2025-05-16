#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:5102.
##

include('compat.inc');

if (description)
{
  script_id(205294);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id(
    "CVE-2021-46939",
    "CVE-2021-47257",
    "CVE-2021-47284",
    "CVE-2021-47304",
    "CVE-2021-47373",
    "CVE-2021-47408",
    "CVE-2021-47461",
    "CVE-2021-47468",
    "CVE-2021-47491",
    "CVE-2021-47548",
    "CVE-2021-47579",
    "CVE-2021-47624",
    "CVE-2022-48632",
    "CVE-2022-48743",
    "CVE-2022-48747",
    "CVE-2022-48757",
    "CVE-2023-52463",
    "CVE-2023-52469",
    "CVE-2023-52471",
    "CVE-2023-52486",
    "CVE-2023-52530",
    "CVE-2023-52619",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2023-52648",
    "CVE-2023-52653",
    "CVE-2023-52658",
    "CVE-2023-52662",
    "CVE-2023-52679",
    "CVE-2023-52707",
    "CVE-2023-52730",
    "CVE-2023-52756",
    "CVE-2023-52762",
    "CVE-2023-52764",
    "CVE-2023-52777",
    "CVE-2023-52784",
    "CVE-2023-52791",
    "CVE-2023-52796",
    "CVE-2023-52803",
    "CVE-2023-52811",
    "CVE-2023-52832",
    "CVE-2023-52834",
    "CVE-2023-52845",
    "CVE-2023-52847",
    "CVE-2023-52864",
    "CVE-2024-2201",
    "CVE-2024-21823",
    "CVE-2024-25739",
    "CVE-2024-26586",
    "CVE-2024-26614",
    "CVE-2024-26640",
    "CVE-2024-26660",
    "CVE-2024-26669",
    "CVE-2024-26686",
    "CVE-2024-26704",
    "CVE-2024-26733",
    "CVE-2024-26740",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26802",
    "CVE-2024-26810",
    "CVE-2024-26837",
    "CVE-2024-26840",
    "CVE-2024-26843",
    "CVE-2024-26852",
    "CVE-2024-26853",
    "CVE-2024-26870",
    "CVE-2024-26878",
    "CVE-2024-26921",
    "CVE-2024-26925",
    "CVE-2024-26940",
    "CVE-2024-26958",
    "CVE-2024-26960",
    "CVE-2024-26961",
    "CVE-2024-27010",
    "CVE-2024-27011",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27025",
    "CVE-2024-27065",
    "CVE-2024-27388",
    "CVE-2024-27395",
    "CVE-2024-27434",
    "CVE-2024-31076",
    "CVE-2024-33621",
    "CVE-2024-35790",
    "CVE-2024-35801",
    "CVE-2024-35807",
    "CVE-2024-35810",
    "CVE-2024-35814",
    "CVE-2024-35847",
    "CVE-2024-35876",
    "CVE-2024-35893",
    "CVE-2024-35896",
    "CVE-2024-35897",
    "CVE-2024-35899",
    "CVE-2024-35900",
    "CVE-2024-35910",
    "CVE-2024-35912",
    "CVE-2024-35924",
    "CVE-2024-35925",
    "CVE-2024-35930",
    "CVE-2024-35937",
    "CVE-2024-35938",
    "CVE-2024-35946",
    "CVE-2024-35947",
    "CVE-2024-35952",
    "CVE-2024-36000",
    "CVE-2024-36005",
    "CVE-2024-36006",
    "CVE-2024-36010",
    "CVE-2024-36016",
    "CVE-2024-36017",
    "CVE-2024-36020",
    "CVE-2024-36025",
    "CVE-2024-36270",
    "CVE-2024-36286",
    "CVE-2024-36489",
    "CVE-2024-36886",
    "CVE-2024-36889",
    "CVE-2024-36896",
    "CVE-2024-36904",
    "CVE-2024-36905",
    "CVE-2024-36917",
    "CVE-2024-36921",
    "CVE-2024-36927",
    "CVE-2024-36929",
    "CVE-2024-36933",
    "CVE-2024-36940",
    "CVE-2024-36941",
    "CVE-2024-36950",
    "CVE-2024-36954",
    "CVE-2024-36960",
    "CVE-2024-36971",
    "CVE-2024-36978",
    "CVE-2024-36979",
    "CVE-2024-38538",
    "CVE-2024-38555",
    "CVE-2024-38573",
    "CVE-2024-38575",
    "CVE-2024-38596",
    "CVE-2024-38615",
    "CVE-2024-38627",
    "CVE-2024-39276",
    "CVE-2024-39472",
    "CVE-2024-39476",
    "CVE-2024-39487",
    "CVE-2024-39502",
    "CVE-2024-40927"
  );
  script_xref(name:"ALSA", value:"2024:5102");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"AlmaLinux 8 : kernel-rt (ALSA-2024:5102)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:5102 advisory.

    * kernel: efivarfs: force RO when remounting if SetVariable is not supported (CVE-2023-52463)
    * kernel: tracing: Restructure trace_clock_global() to never block (CVE-2021-46939)
    * kernel: ext4: avoid online resizing failures due to oversized flex bg (CVE-2023-52622)
    * kernel: net/sched: flower: Fix chain template offload (CVE-2024-26669)
    * kernel: stmmac: Clear variable when destroying workqueue (CVE-2024-26802)
    * kernel: efi: runtime: Fix potential overflow of soft-reserved region size (CVE-2024-26843)
    * kernel: quota: Fix potential NULL pointer dereference (CVE-2024-26878)
    * kernel: TIPC message reassembly use-after-free remote code execution vulnerability (CVE-2024-36886)
    * kernel: SUNRPC: fix a memleak in gss_import_v2_context (CVE-2023-52653)
    * kernel: dmaengine/idxd: hardware erratum allows potential security problem with direct access by
    untrusted application (CVE-2024-21823)
    * kernel: ext4: fix corruption during on-line resize (CVE-2024-35807)
    * kernel: x86/fpu: Keep xfd_state in sync with MSR_IA32_XFD (CVE-2024-35801)
    * kernel: dyndbg: fix old BUG_ON in >control parser (CVE-2024-35947)
    * kernel: net/sched: act_skbmod: prevent kernel-infoleak (CVE-2024-35893)
    * kernel: x86/mce: Make sure to grab mce_sysfs_mutex in set_bank() (CVE-2024-35876)
    * kernel: platform/x86: wmi: Fix opening of char device (CVE-2023-52864)
    * kernel: tipc: Change nla_policy for bearer-related names to NLA_NUL_STRING (CVE-2023-52845)
    * kernel: Revert net/mlx5: Block entering switchdev mode with ns inconsistency (CVE-2023-52658)
    * kernel: crash due to a missing check for leb_size (CVE-2024-25739)
    * kernel: tcp: make sure init the accept_queue's spinlocks once (CVE-2024-26614)
    * kernel: tcp: add sanity checks to rx zerocopy (CVE-2024-26640)
    * kernel: NFSv4.2: fix nfs4_listxattr kernel BUG at mm/usercopy.c:102 (CVE-2024-26870)
    * kernel: nfs: fix UAF in direct writes (CVE-2024-26958)
    * kernel: SUNRPC: fix some memleaks in gssx_dec_option_array (CVE-2024-27388)
    * kernel: wifi: iwlwifi: mvm: don't set the MFP flag for the GTK (CVE-2024-27434)
    * kernel: of: Fix double free in of_parse_phandle_with_args_map (CVE-2023-52679)
    * kernel: scsi: lpfc: Fix possible memory leak in lpfc_rcv_padisc() (CVE-2024-35930)
    * kernel: wifi: iwlwifi: mvm: rfi: fix potential response leaks (CVE-2024-35912)
    * kernel: block: prevent division by zero in blk_rq_stat_sum() (CVE-2024-35925)
    * kernel: wifi: ath11k: decrease MHI channel buffer length to 8KB (CVE-2024-35938)
    * kernel: wifi: cfg80211: check A-MSDU format more carefully (CVE-2024-35937)
    * kernel: wifi: rtw89: fix null pointer access when abort scan (CVE-2024-35946)
    * kernel: netfilter: nf_tables: honor table dormant flag from netdev release event path (CVE-2024-36005)
    * kernel: mm/hugetlb: fix missing hugetlb_lock for resv uncharge (CVE-2024-36000)
    * kernel: mlxsw: spectrum_acl_tcam: Fix incorrect list API usage (CVE-2024-36006)
    * kernel: net: ieee802154: fix null deref in parse dev addr (CVE-2021-47257)
    * kernel: mmc: sdio: fix possible resource leaks in some error paths (CVE-2023-52730)
    * kernel: wifi: ath11k: fix gtk offload status event locking (CVE-2023-52777)
    * (CVE-2023-52832)
    * (CVE-2023-52803)
    * (CVE-2023-52756)
    * (CVE-2023-52834)
    * (CVE-2023-52791)
    * (CVE-2023-52764)
    * (CVE-2021-47468)
    * (CVE-2021-47284)
    * (CVE-2024-36025)
    * (CVE-2024-36941)
    * (CVE-2024-36940)
    * (CVE-2024-36904)
    * (CVE-2024-36896)
    * (CVE-2024-36954)
    * (CVE-2024-36950)
    * (CVE-2024-38575)
    * (CVE-2024-36917)
    * (CVE-2024-36016)
    * (CVE-2023-52762)
    * (CVE-2024-27025)
    * (CVE-2021-47548)
    * (CVE-2023-52619)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-5102.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38627");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 120, 121, 122, 124, 125, 129, 131, 1423, 170, 190, 20, 229, 276, 362, 369, 400, 402, 413, 415, 416, 457, 459, 476, 590, 664, 665, 667, 754, 787, 822, 833, 99);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

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
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-46939', 'CVE-2021-47257', 'CVE-2021-47284', 'CVE-2021-47304', 'CVE-2021-47373', 'CVE-2021-47408', 'CVE-2021-47461', 'CVE-2021-47468', 'CVE-2021-47491', 'CVE-2021-47548', 'CVE-2021-47579', 'CVE-2021-47624', 'CVE-2022-48632', 'CVE-2022-48743', 'CVE-2022-48747', 'CVE-2022-48757', 'CVE-2023-52463', 'CVE-2023-52469', 'CVE-2023-52471', 'CVE-2023-52486', 'CVE-2023-52530', 'CVE-2023-52619', 'CVE-2023-52622', 'CVE-2023-52623', 'CVE-2023-52648', 'CVE-2023-52653', 'CVE-2023-52658', 'CVE-2023-52662', 'CVE-2023-52679', 'CVE-2023-52707', 'CVE-2023-52730', 'CVE-2023-52756', 'CVE-2023-52762', 'CVE-2023-52764', 'CVE-2023-52777', 'CVE-2023-52784', 'CVE-2023-52791', 'CVE-2023-52796', 'CVE-2023-52803', 'CVE-2023-52811', 'CVE-2023-52832', 'CVE-2023-52834', 'CVE-2023-52845', 'CVE-2023-52847', 'CVE-2023-52864', 'CVE-2024-2201', 'CVE-2024-21823', 'CVE-2024-25739', 'CVE-2024-26586', 'CVE-2024-26614', 'CVE-2024-26640', 'CVE-2024-26660', 'CVE-2024-26669', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-26733', 'CVE-2024-26740', 'CVE-2024-26772', 'CVE-2024-26773', 'CVE-2024-26802', 'CVE-2024-26810', 'CVE-2024-26837', 'CVE-2024-26840', 'CVE-2024-26843', 'CVE-2024-26852', 'CVE-2024-26853', 'CVE-2024-26870', 'CVE-2024-26878', 'CVE-2024-26921', 'CVE-2024-26925', 'CVE-2024-26940', 'CVE-2024-26958', 'CVE-2024-26960', 'CVE-2024-26961', 'CVE-2024-27010', 'CVE-2024-27011', 'CVE-2024-27019', 'CVE-2024-27020', 'CVE-2024-27025', 'CVE-2024-27065', 'CVE-2024-27388', 'CVE-2024-27395', 'CVE-2024-27434', 'CVE-2024-31076', 'CVE-2024-33621', 'CVE-2024-35790', 'CVE-2024-35801', 'CVE-2024-35807', 'CVE-2024-35810', 'CVE-2024-35814', 'CVE-2024-35847', 'CVE-2024-35876', 'CVE-2024-35893', 'CVE-2024-35896', 'CVE-2024-35897', 'CVE-2024-35899', 'CVE-2024-35900', 'CVE-2024-35910', 'CVE-2024-35912', 'CVE-2024-35924', 'CVE-2024-35925', 'CVE-2024-35930', 'CVE-2024-35937', 'CVE-2024-35938', 'CVE-2024-35946', 'CVE-2024-35947', 'CVE-2024-35952', 'CVE-2024-36000', 'CVE-2024-36005', 'CVE-2024-36006', 'CVE-2024-36010', 'CVE-2024-36016', 'CVE-2024-36017', 'CVE-2024-36020', 'CVE-2024-36025', 'CVE-2024-36270', 'CVE-2024-36286', 'CVE-2024-36489', 'CVE-2024-36886', 'CVE-2024-36889', 'CVE-2024-36896', 'CVE-2024-36904', 'CVE-2024-36905', 'CVE-2024-36917', 'CVE-2024-36921', 'CVE-2024-36927', 'CVE-2024-36929', 'CVE-2024-36933', 'CVE-2024-36940', 'CVE-2024-36941', 'CVE-2024-36950', 'CVE-2024-36954', 'CVE-2024-36960', 'CVE-2024-36971', 'CVE-2024-36978', 'CVE-2024-36979', 'CVE-2024-38538', 'CVE-2024-38555', 'CVE-2024-38573', 'CVE-2024-38575', 'CVE-2024-38596', 'CVE-2024-38615', 'CVE-2024-38627', 'CVE-2024-39276', 'CVE-2024-39472', 'CVE-2024-39476', 'CVE-2024-39487', 'CVE-2024-39502', 'CVE-2024-40927');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2024:5102');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'kernel-rt-4.18.0-553.16.1.rt7.357.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-core-4.18.0-553.16.1.rt7.357.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-debug-4.18.0-553.16.1.rt7.357.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-debug-core-4.18.0-553.16.1.rt7.357.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-debug-devel-4.18.0-553.16.1.rt7.357.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-debug-kvm-4.18.0-553.16.1.rt7.357.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-debug-modules-4.18.0-553.16.1.rt7.357.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-debug-modules-extra-4.18.0-553.16.1.rt7.357.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-devel-4.18.0-553.16.1.rt7.357.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-kvm-4.18.0-553.16.1.rt7.357.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-modules-4.18.0-553.16.1.rt7.357.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-rt-modules-extra-4.18.0-553.16.1.rt7.357.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
