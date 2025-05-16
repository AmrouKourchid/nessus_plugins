#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:5257. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205467);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2021-47624",
    "CVE-2023-52639",
    "CVE-2024-21823",
    "CVE-2024-26642",
    "CVE-2024-26808",
    "CVE-2024-26993",
    "CVE-2024-27393",
    "CVE-2024-27397",
    "CVE-2024-27403",
    "CVE-2024-35897",
    "CVE-2024-35898",
    "CVE-2024-36886",
    "CVE-2024-36971",
    "CVE-2024-39502",
    "CVE-2024-40978",
    "CVE-2024-41090",
    "CVE-2024-41091"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");
  script_xref(name:"RHSA", value:"2024:5257");

  script_name(english:"RHEL 9 : kernel (RHSA-2024:5257)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:5257 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: netfilter: nf_tables: disallow anonymous set with timeout flag (CVE-2024-26642)

    * kernel: KVM: s390: vsie: fix race during shadow creation (CVE-2023-52639)

    * kernel: netfilter: nft_chain_filter: handle NETDEV_UNREGISTER for inet/ingress basechain
    (CVE-2024-26808)

    * kernel: TIPC message reassembly use-after-free remote code execution vulnerability (CVE-2024-36886)

    * kernel: fs: sysfs: Fix reference leak in sysfs_break_active_protection() (CVE-2024-26993)

    * kernel: dmaengine/idxd: hardware erratum allows potential security problem with direct access by
    untrusted application (CVE-2024-21823)

    * kernel: netfilter: nf_tables: use timestamp to check for set element timeout (CVE-2024-27397)

    * kernel: xen-netfront: Add missing skb_mark_for_recycle (CVE-2024-27393)

    * kernel: netfilter: nft_flow_offload: reset dst in route object after setting up flow (CVE-2024-27403)

    * kernel: netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get() (CVE-2024-35898)

    * kernel: netfilter: nf_tables: discard table flag update with pending basechain deletion (CVE-2024-35897)

    * kernel: ionic: fix use after netif_napi_del() (CVE-2024-39502)

    * kernel: scsi: qedi: Fix crash while reading debugfs attribute (CVE-2024-40978)

    * kernel: net/sunrpc: fix reference count leaks in rpc_sysfs_xprt_state_change (CVE-2021-47624)

    * kernel: virtio-net: tap: mlx5_core short frame denial of service (CVE-2024-41090)

    * kernel: virtio-net: tun: mlx5_core short frame denial of service (CVE-2024-41091)

    * kernel: KEV - Beaky Buzzard (CVE-2024-36971)

    Bug Fix(es):

    * updating nvme firmware, '# nvme list' output does not reflect the new firmware version without
    rebooting.  (JIRA:RHEL-46809)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2298108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299336");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_5257.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0fb5cd8");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:5257");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2024:5257.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36971");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 99, 362, 402, 416, 822);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel-matched");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '9.0')) audit(AUDIT_OS_NOT, 'Red Hat 9.0', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2024:5257');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel9/9.0/aarch64/appstream/debug',
      'content/e4s/rhel9/9.0/aarch64/appstream/os',
      'content/e4s/rhel9/9.0/aarch64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/aarch64/baseos/debug',
      'content/e4s/rhel9/9.0/aarch64/baseos/os',
      'content/e4s/rhel9/9.0/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.0/ppc64le/appstream/debug',
      'content/e4s/rhel9/9.0/ppc64le/appstream/os',
      'content/e4s/rhel9/9.0/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/ppc64le/baseos/debug',
      'content/e4s/rhel9/9.0/ppc64le/baseos/os',
      'content/e4s/rhel9/9.0/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel9/9.0/s390x/appstream/debug',
      'content/e4s/rhel9/9.0/s390x/appstream/os',
      'content/e4s/rhel9/9.0/s390x/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/s390x/baseos/debug',
      'content/e4s/rhel9/9.0/s390x/baseos/os',
      'content/e4s/rhel9/9.0/s390x/baseos/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/appstream/debug',
      'content/e4s/rhel9/9.0/x86_64/appstream/os',
      'content/e4s/rhel9/9.0/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/baseos/debug',
      'content/e4s/rhel9/9.0/x86_64/baseos/os',
      'content/e4s/rhel9/9.0/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-core-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-debug-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-debug-core-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-debug-devel-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-debug-devel-matched-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-debug-modules-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-debug-modules-extra-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-devel-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-devel-matched-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-headers-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-36971']},
      {'reference':'kernel-modules-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-modules-extra-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-tools-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-tools-libs-5.14.0-70.112.1.el9_0', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-tools-libs-5.14.0-70.112.1.el9_0', 'sp':'0', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-tools-libs-5.14.0-70.112.1.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-zfcpdump-5.14.0-70.112.1.el9_0', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-zfcpdump-core-5.14.0-70.112.1.el9_0', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-zfcpdump-devel-5.14.0-70.112.1.el9_0', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-zfcpdump-devel-matched-5.14.0-70.112.1.el9_0', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-zfcpdump-modules-5.14.0-70.112.1.el9_0', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'kernel-zfcpdump-modules-extra-5.14.0-70.112.1.el9_0', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'perf-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']},
      {'reference':'python3-perf-5.14.0-70.112.1.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47624', 'CVE-2023-52639', 'CVE-2024-21823', 'CVE-2024-26642', 'CVE-2024-26808', 'CVE-2024-26993', 'CVE-2024-27393', 'CVE-2024-27397', 'CVE-2024-27403', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-36886', 'CVE-2024-36971', 'CVE-2024-39502', 'CVE-2024-40978', 'CVE-2024-41090', 'CVE-2024-41091']}
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
    'Update Services for SAP Solutions repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-core / kernel-debug / kernel-debug-core / etc');
}
