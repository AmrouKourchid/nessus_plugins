#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1190. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125192);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id(
    "CVE-2016-7913",
    "CVE-2016-8633",
    "CVE-2017-11600",
    "CVE-2017-12190",
    "CVE-2017-13215",
    "CVE-2017-16939",
    "CVE-2017-17558",
    "CVE-2018-1068",
    "CVE-2018-3665",
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2018-18559",
    "CVE-2019-11091"
  );
  script_xref(name:"RHSA", value:"2019:1190");
  script_xref(name:"IAVA", value:"2019-A-0166");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"RHEL 6 : kernel-rt (RHSA-2019:1190)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel-rt.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2019:1190 advisory.

    The kernel-rt packages provide the Real Time Linux Kernel, which enables fine-tuning for systems with
    extremely high determinism requirements.

    Security Fix(es):

    * A flaw was found in the implementation of the fill buffer, a mechanism used by modern CPUs when a
    cache-miss is made on L1 CPU cache. If an attacker can generate a load operation that would create a page
    fault, the execution will continue speculatively with incorrect data from the fill buffer while the data
    is fetched from higher level caches. This response time can be measured to infer data in the fill buffer.
    (CVE-2018-12130)

    * Modern Intel microprocessors implement hardware-level micro-optimizations to improve the performance of
    writing data back to CPU caches. The write operation is split into STA (STore Address) and STD (STore
    Data) sub-operations. These sub-operations allow the processor to hand-off address generation logic into
    these sub-operations for optimized writes. Both of these sub-operations write to a shared distributed
    processor structure called the 'processor store buffer'. As a result, an unprivileged attacker could use
    this flaw to read private data resident within the CPU's processor store buffer. (CVE-2018-12126)

    * Microprocessors use a load port subcomponent to perform load operations from memory or IO. During
    a load operation, the load port receives data from the memory or IO subsystem and then provides the data
    to the CPU registers and operations in the CPUs pipelines. Stale load operations results are stored in
    the 'load port' table until overwritten by newer operations. Certain load-port operations triggered by an
    attacker can be used to reveal data about previous stale requests leaking data back to the attacker via a
    timing side-channel. (CVE-2018-12127)

    * Uncacheable memory on some microprocessors utilizing speculative execution may allow an authenticated
    user to potentially enable information disclosure via a side channel with local access. (CVE-2019-11091)

    * kernel: Buffer overflow in firewire driver via crafted incoming packets (CVE-2016-8633)

    * kernel: crypto: privilege escalation in skcipher_recvmsg function (CVE-2017-13215)

    * Kernel: ipsec: xfrm: use-after-free leading to potential privilege escalation (CVE-2017-16939)

    * kernel: Out-of-bounds write via userland offsets in ebt_entry struct in netfilter/ebtables.c
    (CVE-2018-1068)

    * kernel: Use-after-free due to race condition in AF_PACKET implementation (CVE-2018-18559)

    * kernel: media: use-after-free in [tuner-xc2028] media driver (CVE-2016-7913)

    * kernel: Out-of-bounds access via an XFRM_MSG_MIGRATE xfrm Netlink message (CVE-2017-11600)

    * kernel: memory leak when merging buffers in SCSI IO vectors (CVE-2017-12190)

    * kernel: Unallocated memory access by malicious USB device via bNumInterfaces overflow (CVE-2017-17558)

    * Kernel: FPU state information leakage via lazy FPU restore (CVE-2018-3665)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * update the MRG 2.5.z 3.10 kernel-rt sources (BZ#1692711)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_1190.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2113b7f5");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/mds");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1391490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1402885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1474928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1495089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1517220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1525474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1535173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1552048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1585011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1641878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1646781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1646784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1667782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1692711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1705312");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:1190");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel-rt package based on the guidance in RHSA-2019:1190.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7913");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-18559");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_cwe_id(119, 125, 200, 226, 287, 385, 400, 416, 787);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2016-7913', 'CVE-2016-8633', 'CVE-2017-11600', 'CVE-2017-12190', 'CVE-2017-13215', 'CVE-2017-16939', 'CVE-2017-17558', 'CVE-2018-1068', 'CVE-2018-3665', 'CVE-2018-12126', 'CVE-2018-12127', 'CVE-2018-12130', 'CVE-2018-18559', 'CVE-2019-11091');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2019:1190');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g-execute/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g-execute/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g-execute/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-m/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-m/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-m/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-mgmt/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-mgmt/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-mgmt/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-r/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-r/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-r/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-3.10.0-693.47.2.rt56.641.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-debug-3.10.0-693.47.2.rt56.641.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-debug-devel-3.10.0-693.47.2.rt56.641.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-devel-3.10.0-693.47.2.rt56.641.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-doc-3.10.0-693.47.2.rt56.641.el6rt', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-firmware-3.10.0-693.47.2.rt56.641.el6rt', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-trace-3.10.0-693.47.2.rt56.641.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-trace-devel-3.10.0-693.47.2.rt56.641.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-vanilla-3.10.0-693.47.2.rt56.641.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-vanilla-devel-3.10.0-693.47.2.rt56.641.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-debug / kernel-rt-debug-devel / etc');
}
