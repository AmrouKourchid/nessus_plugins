#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:2621. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194828);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2021-33631",
    "CVE-2022-3640",
    "CVE-2022-42895",
    "CVE-2023-6546",
    "CVE-2024-25744"
  );
  script_xref(name:"RHSA", value:"2024:2621");

  script_name(english:"RHEL 8 : kernel (RHSA-2024:2621)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:2621 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: use after free flaw in l2cap_conn_del in net/bluetooth/l2cap_core.c (CVE-2022-3640)

    * kernel: Information leak in l2cap_parse_conf_req in net/bluetooth/l2cap_core.c (CVE-2022-42895)

    * kernel: GSM multiplexing race condition leads to privilege escalation (CVE-2023-6546,ZDI-CAN-20527)

    * kernel: ext4: kernel bug in ext4_write_inline_data_end() (CVE-2021-33631)

    * kernel: untrusted VMM can trigger int80 syscall handling (CVE-2024-25744)

    Bug Fix(es):

    * kernel: use after free flaw in l2cap_conn_del in net/bluetooth/l2cap_core.c (JIRA:RHEL-18806)

    * tx-checksumming required for accessing port in OpenShift for RHEL 8.6 (JIRA:RHEL-20821)

    * ceph: several cap and snap fixes (JIRA:RHEL-20908)

    * unable to access smsc95xx based interface unless you start outgoing traffic.  (JIRA:RHEL-25718)

    * [RHEL8] ] BUG bio-696 (Not tainted): Poison overwritten  (JIRA:RHEL-26100)

    * kernel: ext4: kernel bug in ext4_write_inline_data_end() (JIRA:RHEL-26330)

    * kernel: Information leak in l2cap_parse_conf_req in net/bluetooth/l2cap_core.c (JIRA:RHEL-18808)

    * kernel: GSM multiplexing race condition leads to privilege escalation (JIRA:RHEL-19953)

    Enhancement(s):

    * [IBM 8.10 FEAT] Upgrade the qeth driver to latest from upstream, e.g. kernel 6.4 (JIRA:RHEL-25810)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_2621.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2fa1ea9");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:2621");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2139610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2147356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2261976");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3640");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-25744");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(190, 416, 824);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/30");

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
  var cve_list = make_list('CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2024:2621');
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
      {'reference':'bpftool-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-core-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-cross-headers-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-debug-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-debug-core-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-debug-devel-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-debug-modules-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-debug-modules-extra-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-devel-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-headers-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-6546']},
      {'reference':'kernel-modules-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-modules-extra-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-tools-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-tools-libs-4.18.0-477.55.1.el8_8', 'sp':'8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-tools-libs-4.18.0-477.55.1.el8_8', 'sp':'8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-tools-libs-4.18.0-477.55.1.el8_8', 'sp':'8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.55.1.el8_8', 'sp':'8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.55.1.el8_8', 'sp':'8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.55.1.el8_8', 'sp':'8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-zfcpdump-4.18.0-477.55.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-zfcpdump-core-4.18.0-477.55.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-zfcpdump-devel-4.18.0-477.55.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-zfcpdump-modules-4.18.0-477.55.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-477.55.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'perf-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']},
      {'reference':'python3-perf-4.18.0-477.55.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-33631', 'CVE-2022-3640', 'CVE-2022-42895', 'CVE-2023-6546', 'CVE-2024-25744']}
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
