#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:4928. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204861);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/22");

  script_cve_id(
    "CVE-2021-47459",
    "CVE-2022-48743",
    "CVE-2023-52458",
    "CVE-2023-52809",
    "CVE-2024-26737",
    "CVE-2024-26773",
    "CVE-2024-26852",
    "CVE-2024-26880",
    "CVE-2024-26982",
    "CVE-2024-27030",
    "CVE-2024-27046",
    "CVE-2024-35857",
    "CVE-2024-35885",
    "CVE-2024-35907",
    "CVE-2024-35952",
    "CVE-2024-36924",
    "CVE-2024-36952",
    "CVE-2024-38580"
  );
  script_xref(name:"RHSA", value:"2024:4928");

  script_name(english:"RHEL 9 : kernel (RHSA-2024:4928)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:4928 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: block: null pointer dereference in ioctl.c when length and logical block size are misaligned
    (CVE-2023-52458)

    * kernel: ext4: avoid allocating blocks from corrupted group in ext4_mb_try_best_found() (CVE-2024-26773)

    * kernel: bpf: Fix racing between bpf_timer_cancel_and_free and bpf_timer_cancel (CVE-2024-26737)

    * kernel: dm: call the resume method on internal suspend (CVE-2024-26880)

    * kernel: net/ipv6: avoid possible UAF in ip6_route_mpath_notify() (CVE-2024-26852)

    * kernel: Squashfs: check the inode number is not the invalid value of zero (CVE-2024-26982)

    * kernel: nfp: flower: handle acti_netdevs allocation failure (CVE-2024-27046)

    * kernel: octeontx2-af: Use separate handlers for interrupts (CVE-2024-27030)

    * kernel: icmp: prevent possible NULL dereferences from icmp_build_probe() (CVE-2024-35857)

    * kernel: mlxbf_gige: call request_irq() after NAPI initialized (CVE-2024-35907)

    * kernel: mlxbf_gige: stop interface during shutdown (CVE-2024-35885)

    * kernel: scsi: libfc: Fix potential NULL pointer dereference in fc_lport_ptp_setup() (CVE-2023-52809)

    * kernel: can: j1939: j1939_netdev_start(): fix UAF for rx_kref of j1939_priv (CVE-2021-47459)

    * kernel: scsi: lpfc: Release hbalock before calling lpfc_worker_wake_up() (CVE-2024-36924)

    * kernel: scsi: lpfc: Move NPIV's transport unregistration to after resource clean up (CVE-2024-36952)

    * kernel: net: amd-xgbe: Fix skb data length underflow (CVE-2022-48743)

    * kernel: epoll: be better about file lifetimes (CVE-2024-38580)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2284506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2284598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293412");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_4928.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd8cc09d");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:4928");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2024:4928.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47459");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(99, 124, 125, 229, 416, 459, 476, 833);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rtla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['9','9.4'])) audit(AUDIT_OS_NOT, 'Red Hat 9.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2024:4928');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel9/9.4/x86_64/appstream/debug',
      'content/aus/rhel9/9.4/x86_64/appstream/os',
      'content/aus/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/aus/rhel9/9.4/x86_64/baseos/debug',
      'content/aus/rhel9/9.4/x86_64/baseos/os',
      'content/aus/rhel9/9.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.4/aarch64/appstream/debug',
      'content/e4s/rhel9/9.4/aarch64/appstream/os',
      'content/e4s/rhel9/9.4/aarch64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.4/aarch64/baseos/debug',
      'content/e4s/rhel9/9.4/aarch64/baseos/os',
      'content/e4s/rhel9/9.4/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.4/ppc64le/appstream/debug',
      'content/e4s/rhel9/9.4/ppc64le/appstream/os',
      'content/e4s/rhel9/9.4/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel9/9.4/ppc64le/baseos/debug',
      'content/e4s/rhel9/9.4/ppc64le/baseos/os',
      'content/e4s/rhel9/9.4/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel9/9.4/s390x/appstream/debug',
      'content/e4s/rhel9/9.4/s390x/appstream/os',
      'content/e4s/rhel9/9.4/s390x/appstream/source/SRPMS',
      'content/e4s/rhel9/9.4/s390x/baseos/debug',
      'content/e4s/rhel9/9.4/s390x/baseos/os',
      'content/e4s/rhel9/9.4/s390x/baseos/source/SRPMS',
      'content/e4s/rhel9/9.4/x86_64/appstream/debug',
      'content/e4s/rhel9/9.4/x86_64/appstream/os',
      'content/e4s/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.4/x86_64/baseos/debug',
      'content/e4s/rhel9/9.4/x86_64/baseos/os',
      'content/e4s/rhel9/9.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.4/x86_64/nfv/debug',
      'content/e4s/rhel9/9.4/x86_64/nfv/os',
      'content/e4s/rhel9/9.4/x86_64/nfv/source/SRPMS',
      'content/e4s/rhel9/9.4/x86_64/rt/debug',
      'content/e4s/rhel9/9.4/x86_64/rt/os',
      'content/e4s/rhel9/9.4/x86_64/rt/source/SRPMS',
      'content/eus/rhel9/9.4/aarch64/appstream/debug',
      'content/eus/rhel9/9.4/aarch64/appstream/os',
      'content/eus/rhel9/9.4/aarch64/appstream/source/SRPMS',
      'content/eus/rhel9/9.4/aarch64/baseos/debug',
      'content/eus/rhel9/9.4/aarch64/baseos/os',
      'content/eus/rhel9/9.4/aarch64/baseos/source/SRPMS',
      'content/eus/rhel9/9.4/aarch64/codeready-builder/debug',
      'content/eus/rhel9/9.4/aarch64/codeready-builder/os',
      'content/eus/rhel9/9.4/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.4/ppc64le/appstream/debug',
      'content/eus/rhel9/9.4/ppc64le/appstream/os',
      'content/eus/rhel9/9.4/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel9/9.4/ppc64le/baseos/debug',
      'content/eus/rhel9/9.4/ppc64le/baseos/os',
      'content/eus/rhel9/9.4/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel9/9.4/ppc64le/codeready-builder/debug',
      'content/eus/rhel9/9.4/ppc64le/codeready-builder/os',
      'content/eus/rhel9/9.4/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.4/s390x/appstream/debug',
      'content/eus/rhel9/9.4/s390x/appstream/os',
      'content/eus/rhel9/9.4/s390x/appstream/source/SRPMS',
      'content/eus/rhel9/9.4/s390x/baseos/debug',
      'content/eus/rhel9/9.4/s390x/baseos/os',
      'content/eus/rhel9/9.4/s390x/baseos/source/SRPMS',
      'content/eus/rhel9/9.4/s390x/codeready-builder/debug',
      'content/eus/rhel9/9.4/s390x/codeready-builder/os',
      'content/eus/rhel9/9.4/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.4/x86_64/appstream/debug',
      'content/eus/rhel9/9.4/x86_64/appstream/os',
      'content/eus/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.4/x86_64/baseos/debug',
      'content/eus/rhel9/9.4/x86_64/baseos/os',
      'content/eus/rhel9/9.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.4/x86_64/codeready-builder/debug',
      'content/eus/rhel9/9.4/x86_64/codeready-builder/os',
      'content/eus/rhel9/9.4/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-7.3.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-devel-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-devel-matched-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-modules-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-modules-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-modules-extra-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-devel-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-devel-matched-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-modules-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-modules-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-modules-extra-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-cross-headers-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-devel-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-devel-matched-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-modules-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-modules-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-modules-extra-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-uki-virt-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-devel-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-devel-matched-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-headers-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-35952']},
      {'reference':'kernel-modules-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-modules-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-modules-extra-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-devel-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-kvm-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-modules-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-modules-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-modules-extra-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-devel-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-kvm-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-modules-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-modules-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-modules-extra-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-libs-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-libs-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-libs-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-libs-devel-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-libs-devel-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-libs-devel-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-uki-virt-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-devel-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-devel-matched-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-modules-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-modules-core-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-modules-extra-5.14.0-427.28.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'libperf-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'perf-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'python3-perf-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'rtla-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'rv-5.14.0-427.28.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9.1/aarch64/appstream/debug',
      'content/dist/rhel9/9.1/aarch64/appstream/os',
      'content/dist/rhel9/9.1/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/aarch64/baseos/debug',
      'content/dist/rhel9/9.1/aarch64/baseos/os',
      'content/dist/rhel9/9.1/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.1/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.1/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.1/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/appstream/debug',
      'content/dist/rhel9/9.1/ppc64le/appstream/os',
      'content/dist/rhel9/9.1/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/baseos/debug',
      'content/dist/rhel9/9.1/ppc64le/baseos/os',
      'content/dist/rhel9/9.1/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.1/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.1/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/appstream/debug',
      'content/dist/rhel9/9.1/s390x/appstream/os',
      'content/dist/rhel9/9.1/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/baseos/debug',
      'content/dist/rhel9/9.1/s390x/baseos/os',
      'content/dist/rhel9/9.1/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.1/s390x/codeready-builder/os',
      'content/dist/rhel9/9.1/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/appstream/debug',
      'content/dist/rhel9/9.1/x86_64/appstream/os',
      'content/dist/rhel9/9.1/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/baseos/debug',
      'content/dist/rhel9/9.1/x86_64/baseos/os',
      'content/dist/rhel9/9.1/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/nfv/debug',
      'content/dist/rhel9/9.1/x86_64/nfv/os',
      'content/dist/rhel9/9.1/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/rt/debug',
      'content/dist/rhel9/9.1/x86_64/rt/os',
      'content/dist/rhel9/9.1/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9.2/aarch64/appstream/debug',
      'content/dist/rhel9/9.2/aarch64/appstream/os',
      'content/dist/rhel9/9.2/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/aarch64/baseos/debug',
      'content/dist/rhel9/9.2/aarch64/baseos/os',
      'content/dist/rhel9/9.2/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.2/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.2/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/appstream/debug',
      'content/dist/rhel9/9.2/ppc64le/appstream/os',
      'content/dist/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/baseos/debug',
      'content/dist/rhel9/9.2/ppc64le/baseos/os',
      'content/dist/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.2/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.2/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/appstream/debug',
      'content/dist/rhel9/9.2/s390x/appstream/os',
      'content/dist/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/baseos/debug',
      'content/dist/rhel9/9.2/s390x/baseos/os',
      'content/dist/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.2/s390x/codeready-builder/os',
      'content/dist/rhel9/9.2/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/appstream/debug',
      'content/dist/rhel9/9.2/x86_64/appstream/os',
      'content/dist/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/baseos/debug',
      'content/dist/rhel9/9.2/x86_64/baseos/os',
      'content/dist/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/nfv/debug',
      'content/dist/rhel9/9.2/x86_64/nfv/os',
      'content/dist/rhel9/9.2/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/rt/debug',
      'content/dist/rhel9/9.2/x86_64/rt/os',
      'content/dist/rhel9/9.2/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9.3/aarch64/appstream/debug',
      'content/dist/rhel9/9.3/aarch64/appstream/os',
      'content/dist/rhel9/9.3/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/aarch64/baseos/debug',
      'content/dist/rhel9/9.3/aarch64/baseos/os',
      'content/dist/rhel9/9.3/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.3/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.3/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/appstream/debug',
      'content/dist/rhel9/9.3/ppc64le/appstream/os',
      'content/dist/rhel9/9.3/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/baseos/debug',
      'content/dist/rhel9/9.3/ppc64le/baseos/os',
      'content/dist/rhel9/9.3/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.3/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.3/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/appstream/debug',
      'content/dist/rhel9/9.3/s390x/appstream/os',
      'content/dist/rhel9/9.3/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/baseos/debug',
      'content/dist/rhel9/9.3/s390x/baseos/os',
      'content/dist/rhel9/9.3/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.3/s390x/codeready-builder/os',
      'content/dist/rhel9/9.3/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/appstream/debug',
      'content/dist/rhel9/9.3/x86_64/appstream/os',
      'content/dist/rhel9/9.3/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/baseos/debug',
      'content/dist/rhel9/9.3/x86_64/baseos/os',
      'content/dist/rhel9/9.3/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/nfv/debug',
      'content/dist/rhel9/9.3/x86_64/nfv/os',
      'content/dist/rhel9/9.3/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/rt/debug',
      'content/dist/rhel9/9.3/x86_64/rt/os',
      'content/dist/rhel9/9.3/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9.4/aarch64/appstream/debug',
      'content/dist/rhel9/9.4/aarch64/appstream/os',
      'content/dist/rhel9/9.4/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/aarch64/baseos/debug',
      'content/dist/rhel9/9.4/aarch64/baseos/os',
      'content/dist/rhel9/9.4/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.4/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.4/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/appstream/debug',
      'content/dist/rhel9/9.4/ppc64le/appstream/os',
      'content/dist/rhel9/9.4/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/baseos/debug',
      'content/dist/rhel9/9.4/ppc64le/baseos/os',
      'content/dist/rhel9/9.4/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.4/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.4/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/appstream/debug',
      'content/dist/rhel9/9.4/s390x/appstream/os',
      'content/dist/rhel9/9.4/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/baseos/debug',
      'content/dist/rhel9/9.4/s390x/baseos/os',
      'content/dist/rhel9/9.4/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.4/s390x/codeready-builder/os',
      'content/dist/rhel9/9.4/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/appstream/debug',
      'content/dist/rhel9/9.4/x86_64/appstream/os',
      'content/dist/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/baseos/debug',
      'content/dist/rhel9/9.4/x86_64/baseos/os',
      'content/dist/rhel9/9.4/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/nfv/debug',
      'content/dist/rhel9/9.4/x86_64/nfv/os',
      'content/dist/rhel9/9.4/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/rt/debug',
      'content/dist/rhel9/9.4/x86_64/rt/os',
      'content/dist/rhel9/9.4/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9.5/aarch64/appstream/debug',
      'content/dist/rhel9/9.5/aarch64/appstream/os',
      'content/dist/rhel9/9.5/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/aarch64/baseos/debug',
      'content/dist/rhel9/9.5/aarch64/baseos/os',
      'content/dist/rhel9/9.5/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.5/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.5/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/appstream/debug',
      'content/dist/rhel9/9.5/ppc64le/appstream/os',
      'content/dist/rhel9/9.5/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/baseos/debug',
      'content/dist/rhel9/9.5/ppc64le/baseos/os',
      'content/dist/rhel9/9.5/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.5/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.5/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/appstream/debug',
      'content/dist/rhel9/9.5/s390x/appstream/os',
      'content/dist/rhel9/9.5/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/baseos/debug',
      'content/dist/rhel9/9.5/s390x/baseos/os',
      'content/dist/rhel9/9.5/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.5/s390x/codeready-builder/os',
      'content/dist/rhel9/9.5/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/appstream/debug',
      'content/dist/rhel9/9.5/x86_64/appstream/os',
      'content/dist/rhel9/9.5/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/baseos/debug',
      'content/dist/rhel9/9.5/x86_64/baseos/os',
      'content/dist/rhel9/9.5/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/nfv/debug',
      'content/dist/rhel9/9.5/x86_64/nfv/os',
      'content/dist/rhel9/9.5/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/rt/debug',
      'content/dist/rhel9/9.5/x86_64/rt/os',
      'content/dist/rhel9/9.5/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9.6/aarch64/appstream/debug',
      'content/dist/rhel9/9.6/aarch64/appstream/os',
      'content/dist/rhel9/9.6/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.6/aarch64/baseos/debug',
      'content/dist/rhel9/9.6/aarch64/baseos/os',
      'content/dist/rhel9/9.6/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.6/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.6/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.6/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.6/aarch64/rt/debug',
      'content/dist/rhel9/9.6/aarch64/rt/os',
      'content/dist/rhel9/9.6/aarch64/rt/source/SRPMS',
      'content/dist/rhel9/9.6/ppc64le/appstream/debug',
      'content/dist/rhel9/9.6/ppc64le/appstream/os',
      'content/dist/rhel9/9.6/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.6/ppc64le/baseos/debug',
      'content/dist/rhel9/9.6/ppc64le/baseos/os',
      'content/dist/rhel9/9.6/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.6/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.6/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.6/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.6/s390x/appstream/debug',
      'content/dist/rhel9/9.6/s390x/appstream/os',
      'content/dist/rhel9/9.6/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.6/s390x/baseos/debug',
      'content/dist/rhel9/9.6/s390x/baseos/os',
      'content/dist/rhel9/9.6/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.6/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.6/s390x/codeready-builder/os',
      'content/dist/rhel9/9.6/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/appstream/debug',
      'content/dist/rhel9/9.6/x86_64/appstream/os',
      'content/dist/rhel9/9.6/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/baseos/debug',
      'content/dist/rhel9/9.6/x86_64/baseos/os',
      'content/dist/rhel9/9.6/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.6/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.6/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/nfv/debug',
      'content/dist/rhel9/9.6/x86_64/nfv/os',
      'content/dist/rhel9/9.6/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/rt/debug',
      'content/dist/rhel9/9.6/x86_64/rt/os',
      'content/dist/rhel9/9.6/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9.7/aarch64/appstream/debug',
      'content/dist/rhel9/9.7/aarch64/appstream/os',
      'content/dist/rhel9/9.7/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.7/aarch64/baseos/debug',
      'content/dist/rhel9/9.7/aarch64/baseos/os',
      'content/dist/rhel9/9.7/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.7/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.7/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.7/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.7/aarch64/nfv/debug',
      'content/dist/rhel9/9.7/aarch64/nfv/os',
      'content/dist/rhel9/9.7/aarch64/nfv/source/SRPMS',
      'content/dist/rhel9/9.7/aarch64/rt/debug',
      'content/dist/rhel9/9.7/aarch64/rt/os',
      'content/dist/rhel9/9.7/aarch64/rt/source/SRPMS',
      'content/dist/rhel9/9.7/ppc64le/appstream/debug',
      'content/dist/rhel9/9.7/ppc64le/appstream/os',
      'content/dist/rhel9/9.7/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.7/ppc64le/baseos/debug',
      'content/dist/rhel9/9.7/ppc64le/baseos/os',
      'content/dist/rhel9/9.7/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.7/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.7/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.7/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.7/s390x/appstream/debug',
      'content/dist/rhel9/9.7/s390x/appstream/os',
      'content/dist/rhel9/9.7/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.7/s390x/baseos/debug',
      'content/dist/rhel9/9.7/s390x/baseos/os',
      'content/dist/rhel9/9.7/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.7/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.7/s390x/codeready-builder/os',
      'content/dist/rhel9/9.7/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.7/x86_64/appstream/debug',
      'content/dist/rhel9/9.7/x86_64/appstream/os',
      'content/dist/rhel9/9.7/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.7/x86_64/baseos/debug',
      'content/dist/rhel9/9.7/x86_64/baseos/os',
      'content/dist/rhel9/9.7/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.7/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.7/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.7/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.7/x86_64/nfv/debug',
      'content/dist/rhel9/9.7/x86_64/nfv/os',
      'content/dist/rhel9/9.7/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.7/x86_64/rt/debug',
      'content/dist/rhel9/9.7/x86_64/rt/os',
      'content/dist/rhel9/9.7/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9/aarch64/appstream/debug',
      'content/dist/rhel9/9/aarch64/appstream/os',
      'content/dist/rhel9/9/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9/aarch64/baseos/debug',
      'content/dist/rhel9/9/aarch64/baseos/os',
      'content/dist/rhel9/9/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9/aarch64/codeready-builder/os',
      'content/dist/rhel9/9/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/aarch64/nfv/debug',
      'content/dist/rhel9/9/aarch64/nfv/os',
      'content/dist/rhel9/9/aarch64/nfv/source/SRPMS',
      'content/dist/rhel9/9/aarch64/rt/debug',
      'content/dist/rhel9/9/aarch64/rt/os',
      'content/dist/rhel9/9/aarch64/rt/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/appstream/debug',
      'content/dist/rhel9/9/ppc64le/appstream/os',
      'content/dist/rhel9/9/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/baseos/debug',
      'content/dist/rhel9/9/ppc64le/baseos/os',
      'content/dist/rhel9/9/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/s390x/appstream/debug',
      'content/dist/rhel9/9/s390x/appstream/os',
      'content/dist/rhel9/9/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9/s390x/baseos/debug',
      'content/dist/rhel9/9/s390x/baseos/os',
      'content/dist/rhel9/9/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9/s390x/codeready-builder/debug',
      'content/dist/rhel9/9/s390x/codeready-builder/os',
      'content/dist/rhel9/9/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/x86_64/appstream/debug',
      'content/dist/rhel9/9/x86_64/appstream/os',
      'content/dist/rhel9/9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9/x86_64/baseos/debug',
      'content/dist/rhel9/9/x86_64/baseos/os',
      'content/dist/rhel9/9/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9/x86_64/codeready-builder/os',
      'content/dist/rhel9/9/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/x86_64/nfv/debug',
      'content/dist/rhel9/9/x86_64/nfv/os',
      'content/dist/rhel9/9/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9/x86_64/rt/debug',
      'content/dist/rhel9/9/x86_64/rt/os',
      'content/dist/rhel9/9/x86_64/rt/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/aarch64/appstream/debug',
      'content/public/ubi/dist/ubi9/9/aarch64/appstream/os',
      'content/public/ubi/dist/ubi9/9/aarch64/appstream/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/aarch64/baseos/debug',
      'content/public/ubi/dist/ubi9/9/aarch64/baseos/os',
      'content/public/ubi/dist/ubi9/9/aarch64/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/aarch64/codeready-builder/debug',
      'content/public/ubi/dist/ubi9/9/aarch64/codeready-builder/os',
      'content/public/ubi/dist/ubi9/9/aarch64/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/ppc64le/appstream/debug',
      'content/public/ubi/dist/ubi9/9/ppc64le/appstream/os',
      'content/public/ubi/dist/ubi9/9/ppc64le/appstream/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/ppc64le/baseos/debug',
      'content/public/ubi/dist/ubi9/9/ppc64le/baseos/os',
      'content/public/ubi/dist/ubi9/9/ppc64le/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/ppc64le/codeready-builder/debug',
      'content/public/ubi/dist/ubi9/9/ppc64le/codeready-builder/os',
      'content/public/ubi/dist/ubi9/9/ppc64le/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/s390x/appstream/debug',
      'content/public/ubi/dist/ubi9/9/s390x/appstream/os',
      'content/public/ubi/dist/ubi9/9/s390x/appstream/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/s390x/baseos/debug',
      'content/public/ubi/dist/ubi9/9/s390x/baseos/os',
      'content/public/ubi/dist/ubi9/9/s390x/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/s390x/codeready-builder/debug',
      'content/public/ubi/dist/ubi9/9/s390x/codeready-builder/os',
      'content/public/ubi/dist/ubi9/9/s390x/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/x86_64/appstream/debug',
      'content/public/ubi/dist/ubi9/9/x86_64/appstream/os',
      'content/public/ubi/dist/ubi9/9/x86_64/appstream/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/x86_64/baseos/debug',
      'content/public/ubi/dist/ubi9/9/x86_64/baseos/os',
      'content/public/ubi/dist/ubi9/9/x86_64/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/x86_64/codeready-builder/debug',
      'content/public/ubi/dist/ubi9/9/x86_64/codeready-builder/os',
      'content/public/ubi/dist/ubi9/9/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-7.3.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-core-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-core-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-devel-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-devel-matched-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-modules-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-modules-core-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-debug-modules-extra-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-devel-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-devel-matched-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-modules-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-modules-core-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-64k-modules-extra-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-core-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-cross-headers-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-core-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-devel-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-devel-matched-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-modules-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-modules-core-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-modules-extra-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-debug-uki-virt-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-devel-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-devel-matched-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-headers-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-35952']},
      {'reference':'kernel-modules-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-modules-core-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-modules-extra-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-core-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-core-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-devel-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-kvm-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-modules-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-modules-core-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-debug-modules-extra-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-devel-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-kvm-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-modules-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-modules-core-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-rt-modules-extra-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-libs-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-libs-5.14.0-427.28.1.el9_4', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-libs-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-libs-devel-5.14.0-427.28.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-libs-devel-5.14.0-427.28.1.el9_4', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-tools-libs-devel-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-uki-virt-5.14.0-427.28.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-5.14.0-427.28.1.el9_4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-core-5.14.0-427.28.1.el9_4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-devel-5.14.0-427.28.1.el9_4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-devel-matched-5.14.0-427.28.1.el9_4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-modules-5.14.0-427.28.1.el9_4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-modules-core-5.14.0-427.28.1.el9_4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'kernel-zfcpdump-modules-extra-5.14.0-427.28.1.el9_4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'libperf-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'perf-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'python3-perf-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'rtla-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']},
      {'reference':'rv-5.14.0-427.28.1.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47459', 'CVE-2022-48743', 'CVE-2023-52458', 'CVE-2023-52809', 'CVE-2024-26737', 'CVE-2024-26773', 'CVE-2024-26852', 'CVE-2024-26880', 'CVE-2024-26982', 'CVE-2024-27030', 'CVE-2024-27046', 'CVE-2024-35857', 'CVE-2024-35885', 'CVE-2024-35907', 'CVE-2024-35952', 'CVE-2024-36924', 'CVE-2024-36952', 'CVE-2024-38580']}
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
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-64k / kernel-64k-core / kernel-64k-debug / etc');
}
