#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2924. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118163);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id(
    "CVE-2018-5390",
    "CVE-2018-5391",
    "CVE-2018-10675",
    "CVE-2018-14634"
  );
  script_xref(name:"RHSA", value:"2018:2924");

  script_name(english:"RHEL 6 : kernel (RHSA-2018:2924)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2018:2924 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * A flaw named SegmentSmack was found in the way the Linux kernel handled specially crafted TCP packets. A
    remote attacker could use this flaw to trigger time and calculation expensive calls to
    tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() functions by sending specially modified packets within
    ongoing TCP sessions which could lead to a CPU saturation and hence a denial of service on the system.
    Maintaining the denial of service condition requires continuous two-way TCP sessions to a reachable open
    port, thus the attacks cannot be performed using spoofed IP addresses. (CVE-2018-5390)

    * A flaw named FragmentSmack was found in the way the Linux kernel handled reassembly of fragmented IPv4
    and IPv6 packets. A remote attacker could use this flaw to trigger time and calculation expensive fragment
    reassembly algorithm by sending specially crafted packets which could lead to a CPU saturation and hence a
    denial of service on the system. (CVE-2018-5391)

    * kernel: mm: use-after-free in do_get_mempolicy function allows local DoS or other unspecified impact
    (CVE-2018-10675)

    * kernel: Integer overflow in Linux's create_elf_tables function (CVE-2018-14634)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

    Red Hat would like to thank Juha-Matti Tilli (Aalto University - Department of Communications and
    Networking and Nokia Bell Labs) for reporting CVE-2018-5390 and CVE-2018-5391 and Qualys Research Labs for
    reporting CVE-2018-14634.

    Bug Fix(es):

    * After updating the system to prevent the L1 Terminal Fault (L1TF) vulnerability, only one thread was
    detected on systems that offer processing of two threads on a single processor core. With this update, the
    __max_smt_threads() function has been fixed. As a result, both threads are now detected correctly in the
    described situation. (BZ#1625334)

    * Previously, a kernel panic occurred when the kernel tried to make an out of bound access to the array
    that describes the L1 Terminal Fault (L1TF) mitigation state on systems without Extended Page Tables (EPT)
    support. This update extends the array of mitigation states to cover all the states, which effectively
    prevents out of bound array access. Also, this update enables rejecting invalid, irrelevant values, that
    might be erroneously provided by the userspace. As a result, the kernel no longer panics in the described
    scenario. (BZ#1629633)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2018/rhsa-2018_2924.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?143db380");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/3553061");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/mutagen-astronomy");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1575065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1601704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1609664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1624498");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:2924");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2018:2924.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14634");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(190, 400, 416);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl", "redhat_repos.nasl");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '6.6')) audit(AUDIT_OS_NOT, 'Red Hat 6.6', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2018-5390', 'CVE-2018-5391', 'CVE-2018-10675', 'CVE-2018-14634');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2018:2924');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.6/x86_64/debug',
      'content/aus/rhel/server/6/6.6/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.6/x86_64/optional/os',
      'content/aus/rhel/server/6/6.6/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.6/x86_64/os',
      'content/aus/rhel/server/6/6.6/x86_64/source/SRPMS',
      'content/tus/rhel/server/6/6.6/x86_64/debug',
      'content/tus/rhel/server/6/6.6/x86_64/optional/debug',
      'content/tus/rhel/server/6/6.6/x86_64/optional/os',
      'content/tus/rhel/server/6/6.6/x86_64/optional/source/SRPMS',
      'content/tus/rhel/server/6/6.6/x86_64/os',
      'content/tus/rhel/server/6/6.6/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-2.6.32-504.76.2.el6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-504.76.2.el6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-504.76.2.el6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-504.76.2.el6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-firmware-2.6.32-504.76.2.el6', 'sp':'6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-504.76.2.el6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-504.76.2.el6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-2.6.32-504.76.2.el6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
    'Advanced Update Support or Telco Extended Update Support repositories.\n' +
    'Access to these repositories requires a paid RHEL subscription.\n';
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-debug / kernel-debug-devel / kernel-devel / etc');
}
