#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:5101.
##

include('compat.inc');

if (description)
{
  script_id(205293);
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
    "CVE-2023-28746",
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
    "CVE-2023-52775",
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
    "CVE-2024-26698",
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
    "CVE-2024-26908",
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
    "CVE-2024-35823",
    "CVE-2024-35824",
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
    "CVE-2024-36945",
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
    "CVE-2024-38598",
    "CVE-2024-38615",
    "CVE-2024-38627",
    "CVE-2024-39276",
    "CVE-2024-39472",
    "CVE-2024-39476",
    "CVE-2024-39487",
    "CVE-2024-39502",
    "CVE-2024-40927",
    "CVE-2024-40974"
  );
  script_xref(name:"ALSA", value:"2024:5101");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"AlmaLinux 8 : kernel (ALSA-2024:5101)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:5101 advisory.

    * kernel: powerpc: Fix access beyond end of drmem array (CVE-2023-52451)
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
    * kernel: Revert net/mlx5: Block entering switchdev mode with ns inconsistency (CVE-2023-52658)
    * kernel: ext4: fix corruption during on-line resize (CVE-2024-35807)
    * kernel: x86/fpu: Keep xfd_state in sync with MSR_IA32_XFD (CVE-2024-35801)
    * kernel: dyndbg: fix old BUG_ON in >control parser (CVE-2024-35947)
    * kernel: net/sched: act_skbmod: prevent kernel-infoleak (CVE-2024-35893)
    * kernel: x86/mce: Make sure to grab mce_sysfs_mutex in set_bank() (CVE-2024-35876)
    * kernel: platform/x86: wmi: Fix opening of char device (CVE-2023-52864)
    * kernel: tipc: Change nla_policy for bearer-related names to NLA_NUL_STRING (CVE-2023-52845)
    * (CVE-2023-28746)
    * (CVE-2023-52847)
    * (CVE-2021-47548)
    * (CVE-2024-36921)
    * (CVE-2024-26921)
    * (CVE-2021-47579)
    * (CVE-2024-36927)
    * (CVE-2024-39276)
    * (CVE-2024-33621)
    * (CVE-2024-27010)
    * (CVE-2024-26960)
    * (CVE-2024-38596)
    * (CVE-2022-48743)
    * (CVE-2024-26733)
    * (CVE-2024-26586)
    * (CVE-2024-26698)
    * (CVE-2023-52619)

    Bug Fix(es):

    * AlmaLinux8.6 - Spinlock statistics may show negative elapsed time and incorrectly formatted output
    (JIRA:AlmaLinux-17678)
    * [AWS][8.9]There are call traces found when booting debug-kernel  for Amazon EC2 r8g.metal-24xl instance
    (JIRA:AlmaLinux-23841)
    * [almalinux8] gfs2: Fix glock shrinker (JIRA:AlmaLinux-32941)
    * lan78xx: Microchip LAN7800 never comes up after unplug and replug (JIRA:AlmaLinux-33437)
    * [Hyper-V][AlmaLinux-8.10.z] Update hv_netvsc driver to TOT (JIRA:AlmaLinux-39074)
    * Use-after-free on proc inode-i_sb triggered by fsnotify (JIRA:AlmaLinux-40167)
    * blk-cgroup: Properly propagate the iostat update up the hierarchy [almalinux-8.10.z]
    (JIRA:AlmaLinux-40939)
    * (JIRA:AlmaLinux-31798)
    * (JIRA:AlmaLinux-10263)
    * (JIRA:AlmaLinux-40901)
    * (JIRA:AlmaLinux-43547)
    * (JIRA:AlmaLinux-34876)

    Enhancement(s):

    * [RFE] Add module parameters 'soft_reboot_cmd' and 'soft_active_on_boot' for customizing softdog
    configuration (JIRA:AlmaLinux-19723)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-5101.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-47018");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-52451");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38627");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 120, 121, 122, 124, 125, 129, 131, 1342, 1423, 170, 190, 20, 229, 276, 362, 369, 400, 401, 402, 413, 415, 416, 457, 459, 476, 590, 664, 665, 667, 690, 754, 787, 822, 833, 99);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

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
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-46939', 'CVE-2021-47257', 'CVE-2021-47284', 'CVE-2021-47304', 'CVE-2021-47373', 'CVE-2021-47408', 'CVE-2021-47461', 'CVE-2021-47468', 'CVE-2021-47491', 'CVE-2021-47548', 'CVE-2021-47579', 'CVE-2021-47624', 'CVE-2022-48632', 'CVE-2022-48743', 'CVE-2022-48747', 'CVE-2022-48757', 'CVE-2023-28746', 'CVE-2023-52463', 'CVE-2023-52469', 'CVE-2023-52471', 'CVE-2023-52486', 'CVE-2023-52530', 'CVE-2023-52619', 'CVE-2023-52622', 'CVE-2023-52623', 'CVE-2023-52648', 'CVE-2023-52653', 'CVE-2023-52658', 'CVE-2023-52662', 'CVE-2023-52679', 'CVE-2023-52707', 'CVE-2023-52730', 'CVE-2023-52756', 'CVE-2023-52762', 'CVE-2023-52764', 'CVE-2023-52775', 'CVE-2023-52777', 'CVE-2023-52784', 'CVE-2023-52791', 'CVE-2023-52796', 'CVE-2023-52803', 'CVE-2023-52811', 'CVE-2023-52832', 'CVE-2023-52834', 'CVE-2023-52845', 'CVE-2023-52847', 'CVE-2023-52864', 'CVE-2024-2201', 'CVE-2024-21823', 'CVE-2024-25739', 'CVE-2024-26586', 'CVE-2024-26614', 'CVE-2024-26640', 'CVE-2024-26660', 'CVE-2024-26669', 'CVE-2024-26686', 'CVE-2024-26698', 'CVE-2024-26704', 'CVE-2024-26733', 'CVE-2024-26740', 'CVE-2024-26772', 'CVE-2024-26773', 'CVE-2024-26802', 'CVE-2024-26810', 'CVE-2024-26837', 'CVE-2024-26840', 'CVE-2024-26843', 'CVE-2024-26852', 'CVE-2024-26853', 'CVE-2024-26870', 'CVE-2024-26878', 'CVE-2024-26908', 'CVE-2024-26921', 'CVE-2024-26925', 'CVE-2024-26940', 'CVE-2024-26958', 'CVE-2024-26960', 'CVE-2024-26961', 'CVE-2024-27010', 'CVE-2024-27011', 'CVE-2024-27019', 'CVE-2024-27020', 'CVE-2024-27025', 'CVE-2024-27065', 'CVE-2024-27388', 'CVE-2024-27395', 'CVE-2024-27434', 'CVE-2024-31076', 'CVE-2024-33621', 'CVE-2024-35790', 'CVE-2024-35801', 'CVE-2024-35807', 'CVE-2024-35810', 'CVE-2024-35814', 'CVE-2024-35823', 'CVE-2024-35824', 'CVE-2024-35847', 'CVE-2024-35876', 'CVE-2024-35893', 'CVE-2024-35896', 'CVE-2024-35897', 'CVE-2024-35899', 'CVE-2024-35900', 'CVE-2024-35910', 'CVE-2024-35912', 'CVE-2024-35924', 'CVE-2024-35925', 'CVE-2024-35930', 'CVE-2024-35937', 'CVE-2024-35938', 'CVE-2024-35946', 'CVE-2024-35947', 'CVE-2024-35952', 'CVE-2024-36000', 'CVE-2024-36005', 'CVE-2024-36006', 'CVE-2024-36010', 'CVE-2024-36016', 'CVE-2024-36017', 'CVE-2024-36020', 'CVE-2024-36025', 'CVE-2024-36270', 'CVE-2024-36286', 'CVE-2024-36489', 'CVE-2024-36886', 'CVE-2024-36889', 'CVE-2024-36896', 'CVE-2024-36904', 'CVE-2024-36905', 'CVE-2024-36917', 'CVE-2024-36921', 'CVE-2024-36927', 'CVE-2024-36929', 'CVE-2024-36933', 'CVE-2024-36940', 'CVE-2024-36941', 'CVE-2024-36945', 'CVE-2024-36950', 'CVE-2024-36954', 'CVE-2024-36960', 'CVE-2024-36971', 'CVE-2024-36978', 'CVE-2024-36979', 'CVE-2024-38538', 'CVE-2024-38555', 'CVE-2024-38573', 'CVE-2024-38575', 'CVE-2024-38596', 'CVE-2024-38598', 'CVE-2024-38615', 'CVE-2024-38627', 'CVE-2024-39276', 'CVE-2024-39472', 'CVE-2024-39476', 'CVE-2024-39487', 'CVE-2024-39502', 'CVE-2024-40927', 'CVE-2024-40974');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2024:5101');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'bpftool-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'bpftool-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'bpftool-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'bpftool-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-abi-stablelists-4.18.0-553.16.1.el8_10', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-core-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-core-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-core-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-core-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-cross-headers-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-cross-headers-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-cross-headers-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-cross-headers-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-core-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-core-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-core-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-core-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-devel-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-devel-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-devel-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-devel-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-devel-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-devel-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-devel-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-devel-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-headers-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-headers-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-headers-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-headers-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-core-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-devel-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'kernel-zfcpdump-modules-extra-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perf-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perf-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perf-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perf-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-perf-4.18.0-553.16.1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-perf-4.18.0-553.16.1.el8_10', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-perf-4.18.0-553.16.1.el8_10', 'cpu':'s390x', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-perf-4.18.0-553.16.1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
