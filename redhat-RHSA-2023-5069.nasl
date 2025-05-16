#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:5069. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181279);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id(
    "CVE-2023-1637",
    "CVE-2023-3390",
    "CVE-2023-3610",
    "CVE-2023-3776",
    "CVE-2023-4004",
    "CVE-2023-4147",
    "CVE-2023-44466",
    "CVE-2023-20593",
    "CVE-2023-21102",
    "CVE-2023-31248",
    "CVE-2023-35001"
  );
  script_xref(name:"RHSA", value:"2023:5069");

  script_name(english:"RHEL 9 : kernel (RHSA-2023:5069)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:5069 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    The following packages have been upgraded to a later upstream version: kernel (5.14.0).

    Security Fix(es):

    * kernel: UAF in nftables when nft_set_lookup_global triggered after handling named and anonymous sets in
    batch requests (CVE-2023-3390)

    * kernel: netfilter: nf_tables: fix chain binding transaction logic in the abort path of NFT_MSG_NEWRULE
    (CVE-2023-3610)

    * kernel: net/sched: cls_fw component can be exploited as result of failure in tcf_change_indev function
    (CVE-2023-3776)

    * kernel: netfilter: use-after-free due to improper element removal in nft_pipapo_remove() (CVE-2023-4004)

    * kernel: netfilter: nf_tables_newrule when adding a rule with NFTA_RULE_CHAIN_ID leads to use-after-free
    (CVE-2023-4147)

    * kernel: nf_tables: use-after-free in nft_chain_lookup_byid() (CVE-2023-31248)

    * kernel: nf_tables: stack-out-of-bounds-read in nft_byteorder_eval() (CVE-2023-35001)

    * kernel: save/restore speculative MSRs during S3 suspend/resume (CVE-2023-1637)

    * hw: amd: Cross-Process Information Leak (CVE-2023-20593)

    * kernel: bypass of shadow stack protection due to a logic error (CVE-2023-21102)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * [Intel 9.3 BUG] [SPR][EMR][FHF] ACPI: Fix system hang during S3 wakeup (BZ#2218026)

    * [Dell 9.2 BUG] Monitor lost after replug WD19TBS to SUT port wiith VGA/DVI to type-C dongle (BZ#2219463)

    * rtmutex: Incorrect waiter woken when requeueing in rt_mutex_adjust_prio_chain() (BZ#2222121)

    * RHEL AWS ARM Instability During Microshift e2e tests (BZ#2223310)

    * RHEL 9.x updates for SEV-SNP guest support (BZ#2224587)

    * Lock state corruption from nested rtmutex blocking in blk_flush_plug() (BZ#2225623)

    * bpf_jit_limit hit again - copy_seccomp() fix (BZ#2226945)

    * libceph: harden msgr2.1 frame segment length checks (BZ#2227070)

    * Temporary values used for the FIPS integrity test should be zeroized after use (BZ#2227768)

    * Important iavf bug fixes July 2023 (BZ#2228156)

    * [i40e/ice] error: Cannot set interface MAC/vlanid to 1e:b7:e2:02:b1:aa/0 for ifname ens4f0 vf 0:
    Resource temporarily unavailable (BZ#2228158)

    * lvconvert --splitcache, --uncache operations getting hung (BZ#2228481)

    * perf: EMR core and uncore PMU support (BZ#2230175)

    * NVIDIA - Grace: Backport i2c: tegra: Set ACPI node as primary fwnode (BZ#2230483)

    * NVIDIA - Grace: Backport i2c: tegra: Fix PEC support for SMBUS block read (BZ#2230488)

    * [Hyper-V][RHEL 9]incomplete fc_transport implementation in storvsc causes null dereference in
    fc_timed_out() (BZ#2230747)

    * Kernel config option CONFIG_CRYPTO_STATS should be disabled until it is enhanced (BZ#2231850)

    * [RHEL 9][Hyper-V]Excessive hv_storvsc driver logging with srb_status  SRB_STATUS_INTERNAL_ERROR  (0x30)
    (BZ#2231990)

    * RHEL-9: WARNING: bad unlock balance detected! (BZ#2232213)

    * NVIDIA - Grace: Backport drm/ast patch expected for kernel 6.4 (BZ#2232302)

    * [Lenovo 9.1 bug]   RHEL 9 will hang when echo c > /proc/sysrq-trigger. (BZ#2232700)

    * [RHEL-9] bz2022169 in /kernel/general/process/reg-suit fails on aarch64  (/proc/[pid]/wchan broken)
    (BZ#2233928)

    Enhancement(s):

    * [Intel 9.3 FEAT] cpufreq: intel_pstate: Enable HWP IO boost for all servers (BZ#2210270)

    * [Dell 9.3 FEAT] - New MB with AMP Codec Change on Maya Bay (audio driver) (BZ#2218960)

    * [Lenovo 9.3 FEAT] MDRAID - Update to the latest upstream (BZ#2221170)

    * [Intel 9.3 FEAT] [EMR] Add EMR support to uncore-frequency driver (BZ#2230169)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_5069.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3606e4e3");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:5069");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2181891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2217845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2220892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2220893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225275");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44466");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-4004");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 125, 200, 413, 416, 1239);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.2");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rtla");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['9','9.2'])) audit(AUDIT_OS_NOT, 'Red Hat 9.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2023:5069');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel9/9.2/x86_64/appstream/debug',
      'content/aus/rhel9/9.2/x86_64/appstream/os',
      'content/aus/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/aus/rhel9/9.2/x86_64/baseos/debug',
      'content/aus/rhel9/9.2/x86_64/baseos/os',
      'content/aus/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/aarch64/appstream/debug',
      'content/e4s/rhel9/9.2/aarch64/appstream/os',
      'content/e4s/rhel9/9.2/aarch64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/aarch64/baseos/debug',
      'content/e4s/rhel9/9.2/aarch64/baseos/os',
      'content/e4s/rhel9/9.2/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/appstream/debug',
      'content/e4s/rhel9/9.2/ppc64le/appstream/os',
      'content/e4s/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/baseos/debug',
      'content/e4s/rhel9/9.2/ppc64le/baseos/os',
      'content/e4s/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/appstream/debug',
      'content/e4s/rhel9/9.2/s390x/appstream/os',
      'content/e4s/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/baseos/debug',
      'content/e4s/rhel9/9.2/s390x/baseos/os',
      'content/e4s/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/appstream/debug',
      'content/e4s/rhel9/9.2/x86_64/appstream/os',
      'content/e4s/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/baseos/debug',
      'content/e4s/rhel9/9.2/x86_64/baseos/os',
      'content/e4s/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/appstream/debug',
      'content/eus/rhel9/9.2/aarch64/appstream/os',
      'content/eus/rhel9/9.2/aarch64/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/baseos/debug',
      'content/eus/rhel9/9.2/aarch64/baseos/os',
      'content/eus/rhel9/9.2/aarch64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/codeready-builder/debug',
      'content/eus/rhel9/9.2/aarch64/codeready-builder/os',
      'content/eus/rhel9/9.2/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/appstream/debug',
      'content/eus/rhel9/9.2/ppc64le/appstream/os',
      'content/eus/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/baseos/debug',
      'content/eus/rhel9/9.2/ppc64le/baseos/os',
      'content/eus/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/debug',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/os',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/appstream/debug',
      'content/eus/rhel9/9.2/s390x/appstream/os',
      'content/eus/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/baseos/debug',
      'content/eus/rhel9/9.2/s390x/baseos/os',
      'content/eus/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/codeready-builder/debug',
      'content/eus/rhel9/9.2/s390x/codeready-builder/os',
      'content/eus/rhel9/9.2/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/appstream/debug',
      'content/eus/rhel9/9.2/x86_64/appstream/os',
      'content/eus/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/baseos/debug',
      'content/eus/rhel9/9.2/x86_64/baseos/os',
      'content/eus/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/debug',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/os',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-7.0.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-core-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-core-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-devel-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-devel-matched-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-modules-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-modules-core-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-modules-extra-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-devel-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-devel-matched-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-modules-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-modules-core-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-modules-extra-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-core-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-cross-headers-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-44466']},
      {'reference':'kernel-debug-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-core-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-devel-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-devel-matched-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-modules-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-modules-core-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-modules-extra-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-uki-virt-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-devel-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-devel-matched-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-headers-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-44466']},
      {'reference':'kernel-modules-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-modules-core-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-modules-extra-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-uki-virt-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-core-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-devel-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-devel-matched-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-modules-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-modules-core-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-modules-extra-5.14.0-284.30.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'perf-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'python3-perf-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'rtla-5.14.0-284.30.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']}
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
      'content/dist/rhel9/9.6/aarch64/appstream/debug',
      'content/dist/rhel9/9.6/aarch64/appstream/os',
      'content/dist/rhel9/9.6/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.6/aarch64/baseos/debug',
      'content/dist/rhel9/9.6/aarch64/baseos/os',
      'content/dist/rhel9/9.6/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.6/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.6/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.6/aarch64/codeready-builder/source/SRPMS',
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
      'content/dist/rhel9/9.7/aarch64/appstream/debug',
      'content/dist/rhel9/9.7/aarch64/appstream/os',
      'content/dist/rhel9/9.7/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.7/aarch64/baseos/debug',
      'content/dist/rhel9/9.7/aarch64/baseos/os',
      'content/dist/rhel9/9.7/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.7/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.7/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.7/aarch64/codeready-builder/source/SRPMS',
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
      'content/dist/rhel9/9/aarch64/appstream/debug',
      'content/dist/rhel9/9/aarch64/appstream/os',
      'content/dist/rhel9/9/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9/aarch64/baseos/debug',
      'content/dist/rhel9/9/aarch64/baseos/os',
      'content/dist/rhel9/9/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9/aarch64/codeready-builder/os',
      'content/dist/rhel9/9/aarch64/codeready-builder/source/SRPMS',
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
      {'reference':'bpftool-7.0.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-core-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-core-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-devel-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-devel-matched-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-modules-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-modules-core-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-debug-modules-extra-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-devel-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-devel-matched-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-modules-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-modules-core-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-64k-modules-extra-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-core-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-cross-headers-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-44466']},
      {'reference':'kernel-debug-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-core-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-devel-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-devel-matched-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-modules-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-modules-core-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-modules-extra-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-debug-uki-virt-5.14.0-284.30.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-devel-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-devel-matched-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-headers-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-44466']},
      {'reference':'kernel-modules-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-modules-core-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-modules-extra-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-5.14.0-284.30.1.el9_2', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-5.14.0-284.30.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.30.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.30.1.el9_2', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.30.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-uki-virt-5.14.0-284.30.1.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-5.14.0-284.30.1.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-core-5.14.0-284.30.1.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-devel-5.14.0-284.30.1.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-devel-matched-5.14.0-284.30.1.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-modules-5.14.0-284.30.1.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-modules-core-5.14.0-284.30.1.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-modules-extra-5.14.0-284.30.1.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'perf-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'python3-perf-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'rtla-5.14.0-284.30.1.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001', 'CVE-2023-44466']}
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
      severity   : SECURITY_HOLE,
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
