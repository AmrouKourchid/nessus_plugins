#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:1306. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192035);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2022-0480",
    "CVE-2022-3545",
    "CVE-2022-38096",
    "CVE-2022-40982",
    "CVE-2023-1192",
    "CVE-2023-2163",
    "CVE-2023-2166",
    "CVE-2023-2176",
    "CVE-2023-3268",
    "CVE-2023-3390",
    "CVE-2023-3609",
    "CVE-2023-4459",
    "CVE-2023-4622",
    "CVE-2023-5717",
    "CVE-2023-6546",
    "CVE-2023-6932",
    "CVE-2023-7192",
    "CVE-2023-38409",
    "CVE-2023-40283",
    "CVE-2024-0646"
  );
  script_xref(name:"RHSA", value:"2024:1306");

  script_name(english:"RHEL 9 : kernel-rt (RHSA-2024:1306)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel-rt.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:1306 advisory.

    The kernel-rt packages provide the Real Time Linux Kernel, which enables fine-tuning for systems with
    extremely high determinism requirements.

    Security Fix(es):

    * memcg does not limit the number of POSIX file locks allowing memory exhaustion (CVE-2022-0480)

    * vmwgfx: NULL pointer dereference in vmw_cmd_dx_define_query (CVE-2022-38096)

    * use-after-free in smb2_is_status_io_timeout() (CVE-2023-1192)

    * nfp: use-after-free in area_cache_get() (CVE-2022-3545)

    * NULL pointer dereference in can_rcv_filter (CVE-2023-2166)

    * Slab-out-of-bound read in compare_netdev_and_ip (CVE-2023-2176)

    * UAF in nftables when nft_set_lookup_global triggered after handling named and anonymous sets in batch
    requests (CVE-2023-3390)

    * out-of-bounds access in relay_file_read (CVE-2023-3268)

    * vmxnet3: NULL pointer dereference in vmxnet3_rq_cleanup() (CVE-2023-4459)

    * Gather Data Sampling (GDS) side channel vulnerability (CVE-2022-40982,Downfall)

    * net/sched: cls_u32 component reference counter leak if tcf_change_indev() fails (CVE-2023-3609)

    * fbcon: out-of-sync arrays in fbcon_mode_deleted due to wrong con2fb_map assignment (CVE-2023-38409)

    * Race Condition leading to UAF in Unix Socket could happen in sk_receive_queue ()

    * use-after-free in l2cap_sock_release in net/bluetooth/l2cap_sock.c (CVE-2023-40283)

    * use after free in unix_stream_sendpage (CVE-2023-4622)

    * bpf: Incorrect verifier pruning leads to unsafe code paths being incorrectly marked as safe
    (CVE-2023-2163)

    * A heap out-of-bounds write when function perf_read_group is called and sibling_list is smaller than its
    child's sibling_list (CVE-2023-5717)

    * ktls overwrites readonly memory pages when using function splice with a ktls socket as destination
    (CVE-2024-0646)

    * use-after-free in IPv4 IGMP (CVE-2023-6932)

    * GSM multiplexing race condition leads to privilege escalation (CVE-2023-6546,ZDI-CAN-20527)

    * refcount leak in ctnetlink_create_conntrack() (CVE-2023-7192)

    Bug Fix(es):

    * fbcon: out-of-sync arrays in fbcon_mode_deleted due to wrong con2fb_map assignment (JIRA:RHEL-1107)

    * out-of-bounds access in relay_file_read (JIRA:RHEL-1749)

    * vmxnet3: NULL pointer dereference in vmxnet3_rq_cleanup() (JIRA:RHEL-18085)

    * NULL pointer dereference in can_rcv_filter (JIRA:RHEL-19524)

    * update RT source tree to the latest RHEL-9.0.z Batch 15 (JIRA:RHEL-21555)

    * Gather Data Sampling (GDS) side channel vulnerability (JIRA:RHEL-9285)

    * A heap out-of-bounds write (JIRA:RHEL-18011)

    * Slab-out-of-bound read in compare_netdev_and_ip (JIRA:RHEL-19398)

    * A flaw leading to a use-after-free in area_cache_get() (JIRA:RHEL-19534)

    * Incorrect verifier pruning leads to unsafe code paths being incorrectly marked as safe (JIRA:RHEL-8980)

    * various flaws (JIRA:RHEL-16150)

    * refcount leak in ctnetlink_create_conntrack() (JIRA:RHEL-20311)

    * use-after-free in l2cap_sock_release in net/bluetooth/l2cap_sock.c (JIRA:RHEL-20502)

    * ktls overwrites readonly memory pages when using function splice with a ktls socket as destination
    (JIRA:RHEL-22095)

    * use-after-free in smb2_is_status_io_timeout() (JIRA:RHEL-15171)

    * use-after-free in IPv4 IGMP (JIRA:RHEL-21658)

    * memcg does not limit the number of POSIX file locks allowing memory exhaustion (JIRA:RHEL-8996)

    * GSM multiplexing race condition leads to privilege escalation (JIRA:RHEL-19968)

    * NULL pointer dereference in vmw_cmd_dx_define_query (JIRA:RHEL-22751)

    * kernel: sched/membarrier: reduce the ability to hammer on sys_membarrier
    (JIRA:RHEL-26381)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_1306.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?292b41a9");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2049700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2133452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2154178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2161310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2187813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2187931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2215502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2219268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2223949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2230042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2230094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2231800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2240249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2246945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2256279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267695");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:1306");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel-rt package based on the guidance in RHSA-2024:1306.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0646");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2163");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-3390");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(125, 129, 200, 401, 415, 416, 476, 682, 770, 787);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-extra");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '9.0')) audit(AUDIT_OS_NOT, 'Red Hat 9.0', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2022-0480', 'CVE-2022-3545', 'CVE-2022-38096', 'CVE-2022-40982', 'CVE-2023-1192', 'CVE-2023-2163', 'CVE-2023-2166', 'CVE-2023-2176', 'CVE-2023-3268', 'CVE-2023-3390', 'CVE-2023-3609', 'CVE-2023-4459', 'CVE-2023-4622', 'CVE-2023-5717', 'CVE-2023-6546', 'CVE-2023-6932', 'CVE-2023-7192', 'CVE-2023-38409', 'CVE-2023-40283', 'CVE-2024-0646');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2024:1306');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel9/9.0/x86_64/nfv/debug',
      'content/e4s/rhel9/9.0/x86_64/nfv/os',
      'content/e4s/rhel9/9.0/x86_64/nfv/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/rt/debug',
      'content/e4s/rhel9/9.0/x86_64/rt/os',
      'content/e4s/rhel9/9.0/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-5.14.0-70.93.1.rt21.165.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-5.14.0-70.93.1.rt21.165.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-5.14.0-70.93.1.rt21.165.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-5.14.0-70.93.1.rt21.165.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-5.14.0-70.93.1.rt21.165.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-5.14.0-70.93.1.rt21.165.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-5.14.0-70.93.1.rt21.165.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-5.14.0-70.93.1.rt21.165.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-5.14.0-70.93.1.rt21.165.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-5.14.0-70.93.1.rt21.165.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-5.14.0-70.93.1.rt21.165.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-5.14.0-70.93.1.rt21.165.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
