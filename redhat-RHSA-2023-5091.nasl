#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:5091. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181283);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id(
    "CVE-2023-1637",
    "CVE-2023-3390",
    "CVE-2023-3610",
    "CVE-2023-3776",
    "CVE-2023-4004",
    "CVE-2023-4147",
    "CVE-2023-20593",
    "CVE-2023-21102",
    "CVE-2023-31248",
    "CVE-2023-35001"
  );
  script_xref(name:"RHSA", value:"2023:5091");

  script_name(english:"RHEL 9 : kernel-rt (RHSA-2023:5091)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel-rt.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:5091 advisory.

    The kernel-rt packages provide the Real Time Linux Kernel, which enables fine-tuning for systems with
    extremely high determinism requirements.

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

    * kernel-rt: update RT source tree to the latest RHEL-9.2.z3 Batch (BZ#2228482)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_5091.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9a1d3a2");
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
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:5091");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel-rt package based on the guidance in RHSA-2023:5091.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4147");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-4004");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(125, 200, 413, 416, 1239);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.2");
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
  var cve_list = make_list('CVE-2023-1637', 'CVE-2023-3390', 'CVE-2023-3610', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-4147', 'CVE-2023-20593', 'CVE-2023-21102', 'CVE-2023-31248', 'CVE-2023-35001');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2023:5091');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9.1/x86_64/nfv/debug',
      'content/dist/rhel9/9.1/x86_64/nfv/os',
      'content/dist/rhel9/9.1/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/rt/debug',
      'content/dist/rhel9/9.1/x86_64/rt/os',
      'content/dist/rhel9/9.1/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/nfv/debug',
      'content/dist/rhel9/9.2/x86_64/nfv/os',
      'content/dist/rhel9/9.2/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/rt/debug',
      'content/dist/rhel9/9.2/x86_64/rt/os',
      'content/dist/rhel9/9.2/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/nfv/debug',
      'content/dist/rhel9/9.3/x86_64/nfv/os',
      'content/dist/rhel9/9.3/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/rt/debug',
      'content/dist/rhel9/9.3/x86_64/rt/os',
      'content/dist/rhel9/9.3/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/nfv/debug',
      'content/dist/rhel9/9.4/x86_64/nfv/os',
      'content/dist/rhel9/9.4/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/rt/debug',
      'content/dist/rhel9/9.4/x86_64/rt/os',
      'content/dist/rhel9/9.4/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/nfv/debug',
      'content/dist/rhel9/9.5/x86_64/nfv/os',
      'content/dist/rhel9/9.5/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/rt/debug',
      'content/dist/rhel9/9.5/x86_64/rt/os',
      'content/dist/rhel9/9.5/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/nfv/debug',
      'content/dist/rhel9/9.6/x86_64/nfv/os',
      'content/dist/rhel9/9.6/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/rt/debug',
      'content/dist/rhel9/9.6/x86_64/rt/os',
      'content/dist/rhel9/9.6/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9.7/x86_64/nfv/debug',
      'content/dist/rhel9/9.7/x86_64/nfv/os',
      'content/dist/rhel9/9.7/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9.7/x86_64/rt/debug',
      'content/dist/rhel9/9.7/x86_64/rt/os',
      'content/dist/rhel9/9.7/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9/x86_64/nfv/debug',
      'content/dist/rhel9/9/x86_64/nfv/os',
      'content/dist/rhel9/9/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9/x86_64/rt/debug',
      'content/dist/rhel9/9/x86_64/rt/os',
      'content/dist/rhel9/9/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-core-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-core-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-5.14.0-284.30.1.rt14.315.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/e4s/rhel9/9.2/x86_64/nfv/debug',
      'content/e4s/rhel9/9.2/x86_64/nfv/os',
      'content/e4s/rhel9/9.2/x86_64/nfv/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/rt/debug',
      'content/e4s/rhel9/9.2/x86_64/rt/os',
      'content/e4s/rhel9/9.2/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-core-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-core-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-5.14.0-284.30.1.rt14.315.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-core / kernel-rt-debug / kernel-rt-debug-core / etc');
}
