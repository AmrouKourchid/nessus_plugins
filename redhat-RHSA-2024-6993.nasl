#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:6993. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207689);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/11");

  script_cve_id(
    "CVE-2021-47352",
    "CVE-2021-47356",
    "CVE-2021-47384",
    "CVE-2021-47468",
    "CVE-2021-47566",
    "CVE-2022-48638",
    "CVE-2023-52434",
    "CVE-2023-52439",
    "CVE-2023-52522",
    "CVE-2023-52784",
    "CVE-2023-52811",
    "CVE-2023-52864",
    "CVE-2024-26665",
    "CVE-2024-26698",
    "CVE-2024-26772",
    "CVE-2024-26826",
    "CVE-2024-26851",
    "CVE-2024-26908",
    "CVE-2024-26923",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27399",
    "CVE-2024-35898",
    "CVE-2024-35969",
    "CVE-2024-36005",
    "CVE-2024-36016",
    "CVE-2024-36270",
    "CVE-2024-36929",
    "CVE-2024-36978",
    "CVE-2024-38573",
    "CVE-2024-38598",
    "CVE-2024-38615",
    "CVE-2024-40995",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41071",
    "CVE-2024-41093",
    "CVE-2024-42154"
  );
  script_xref(name:"RHSA", value:"2024:6993");

  script_name(english:"RHEL 8 : kernel (RHSA-2024:6993)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:6993 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: uio: Fix use-after-free in uio_open (CVE-2023-52439)

    * kernel: smb: client: fix potential OOBs in smb2_parse_contexts() (CVE-2023-52434)

    * kernel: net: fix possible store tearing in neigh_periodic_work() (CVE-2023-52522)

    * kernel: tunnels: fix out of bounds access when building IPv6 PMTU error (CVE-2024-26665)

    * kernel: hv_netvsc: Fix race condition between netvsc_probe and netvsc_remove (CVE-2024-26698)

    * kernel: ext4: avoid allocating blocks from corrupted group in ext4_mb_find_by_goal() (CVE-2024-26772)

    * kernel: mptcp: fix data re-injection from stale subflow (CVE-2024-26826)

    * kernel: x86/xen: Add some null pointer checking to smp.c (CVE-2024-26908)

    * kernel: netfilter: nf_conntrack_h323: Add protection for bmp length out of range (CVE-2024-26851)

    * kernel: af_unix: Fix garbage collector racing against connect() (CVE-2024-26923)

    * kernel: cgroup: cgroup_get_from_id() must check the looked-up kn is a directory (CVE-2022-48638)

    * kernel: netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get() (CVE-2024-27020)

    * kernel: netfilter: nf_tables: Fix potential data-race in __nft_obj_type_get() (CVE-2024-27019)

    * kernel: Bluetooth: l2cap: fix null-ptr-deref in l2cap_chan_timeout (CVE-2024-27399)

    * kernel: netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get() (CVE-2024-35898)

    * kernel: ipv6: fix race condition between ipv6_get_ifaddr and ipv6_del_addr (CVE-2024-35969)

    * kernel: netfilter: nf_tables: honor table dormant flag from netdev release event path (CVE-2024-36005)

    * kernel: hwmon: (w83793) Fix NULL pointer dereference by removing unnecessary structure field
    (CVE-2021-47384)

    * kernel: mISDN: fix possible use-after-free in HFC_cleanup() (CVE-2021-47356)

    * kernel: virtio-net: Add validation for used length (CVE-2021-47352)

    * kernel: platform/x86: wmi: Fix opening of char device (CVE-2023-52864)

    * kernel: scsi: ibmvfc: Remove BUG_ON in the case of an empty event pool (CVE-2023-52811)

    * kernel: bonding: stop the device in bond_setup_by_slave() (CVE-2023-52784)

    * kernel: isdn: mISDN: Fix sleeping function called from invalid context (CVE-2021-47468)

    * kernel: proc/vmcore: fix clearing user buffer by properly using clear_user() (CVE-2021-47566)

    * kernel: tty: n_gsm: fix possible out-of-bounds in gsm0_receive() (CVE-2024-36016)

    * kernel: net: core: reject skb_copy(_expand) for fraglist GSO skbs (CVE-2024-36929)

    * kernel: net: sched: sch_multiq: fix possible OOB write in multiq_tune() (CVE-2024-36978)

    * kernel: cpufreq: exit() callback is optional (CVE-2024-38615)

    * kernel: md: fix resync softlockup when bitmap size is less than array size (CVE-2024-38598)

    * kernel: cppc_cpufreq: Fix possible null pointer dereference (CVE-2024-38573)

    * kernel: netfilter: tproxy: bail out if IP has been disabled on the device (CVE-2024-36270)

    * kernel: net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc() (CVE-2024-40995)

    * kernel: udp: Set SOCK_RCU_FREE earlier in udp_lib_get_port() (CVE-2024-41041)

    * kernel: ppp: reject claimed-as-LCP but actually malformed packets (CVE-2024-41044)

    * kernel: wifi: mac80211: Avoid address calculations via out of bounds array indexing (CVE-2024-41071)

    * kernel: drm/amdgpu: avoid using null object of framebuffer (CVE-2024-41093)

    * kernel: tcp_metrics: validate source addr length (CVE-2024-42154)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_6993.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1943e146");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2284496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301522");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:6993");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2024:6993.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52434");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 99, 125, 130, 229, 362, 402, 416, 459, 476, 501, 588, 667, 690, 787, 822, 833, 911);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.8')) audit(AUDIT_OS_NOT, 'Red Hat 8.8', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-47352', 'CVE-2021-47356', 'CVE-2021-47384', 'CVE-2021-47468', 'CVE-2021-47566', 'CVE-2022-48638', 'CVE-2023-52434', 'CVE-2023-52439', 'CVE-2023-52522', 'CVE-2023-52784', 'CVE-2023-52811', 'CVE-2023-52864', 'CVE-2024-26665', 'CVE-2024-26698', 'CVE-2024-26772', 'CVE-2024-26826', 'CVE-2024-26851', 'CVE-2024-26908', 'CVE-2024-26923', 'CVE-2024-27019', 'CVE-2024-27020', 'CVE-2024-27399', 'CVE-2024-35898', 'CVE-2024-35969', 'CVE-2024-36005', 'CVE-2024-36016', 'CVE-2024-36270', 'CVE-2024-36929', 'CVE-2024-36978', 'CVE-2024-38573', 'CVE-2024-38598', 'CVE-2024-38615', 'CVE-2024-40995', 'CVE-2024-41041', 'CVE-2024-41044', 'CVE-2024-41071', 'CVE-2024-41093', 'CVE-2024-42154');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2024:6993');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel8/8.8/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.8/ppc64le/baseos/os',
      'content/e4s/rhel8/8.8/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.8/x86_64/baseos/debug',
      'content/e4s/rhel8/8.8/x86_64/baseos/os',
      'content/e4s/rhel8/8.8/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/aarch64/baseos/debug',
      'content/eus/rhel8/8.8/aarch64/baseos/os',
      'content/eus/rhel8/8.8/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.8/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.8/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.8/ppc64le/baseos/debug',
      'content/eus/rhel8/8.8/ppc64le/baseos/os',
      'content/eus/rhel8/8.8/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.8/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.8/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.8/s390x/baseos/debug',
      'content/eus/rhel8/8.8/s390x/baseos/os',
      'content/eus/rhel8/8.8/s390x/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/s390x/codeready-builder/debug',
      'content/eus/rhel8/8.8/s390x/codeready-builder/os',
      'content/eus/rhel8/8.8/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.8/x86_64/baseos/debug',
      'content/eus/rhel8/8.8/x86_64/baseos/os',
      'content/eus/rhel8/8.8/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.8/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.8/x86_64/codeready-builder/source/SRPMS',
      'content/tus/rhel8/8.8/x86_64/baseos/debug',
      'content/tus/rhel8/8.8/x86_64/baseos/os',
      'content/tus/rhel8/8.8/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-cross-headers-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-477.74.1.el8_8', 'sp':'8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-477.74.1.el8_8', 'sp':'8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-477.74.1.el8_8', 'sp':'8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.74.1.el8_8', 'sp':'8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.74.1.el8_8', 'sp':'8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.74.1.el8_8', 'sp':'8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-4.18.0-477.74.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-4.18.0-477.74.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-4.18.0-477.74.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-4.18.0-477.74.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-477.74.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-4.18.0-477.74.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
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
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-core / kernel-cross-headers / etc');
}
