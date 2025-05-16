#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1787. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(85979);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/03");

  script_cve_id(
    "CVE-2014-9585",
    "CVE-2015-0275",
    "CVE-2015-1333",
    "CVE-2015-3212",
    "CVE-2015-5364",
    "CVE-2015-5366"
  );
  script_xref(name:"RHSA", value:"2015:1787");

  script_name(english:"RHEL 6 : kernel-rt (RHSA-2015:1787)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2015:1787 advisory.

    The kernel-rt packages contain the Linux kernel, the core of any Linux
    operating system.

    * Two flaws were found in the way the Linux kernel's networking
    implementation handled UDP packets with incorrect checksum values. A remote
    attacker could potentially use these flaws to trigger an infinite loop in
    the kernel, resulting in a denial of service on the system, or cause a
    denial of service in applications using the edge triggered epoll
    functionality. (CVE-2015-5364, CVE-2015-5366, Important)

    * A flaw was found in the way the Linux kernel's ext4 file system handled
    the page size > block size condition when the fallocate zero range
    functionality was used. A local attacker could use this flaw to crash the
    system. (CVE-2015-0275, Moderate)

    * It was found that the Linux kernel's keyring implementation would leak
    memory when adding a key to a keyring via the add_key() function. A local
    attacker could use this flaw to exhaust all available memory on the system.
    (CVE-2015-1333, Moderate)

    * A race condition flaw was found in the way the Linux kernel's SCTP
    implementation handled Address Configuration lists when performing Address
    Configuration Change (ASCONF). A local attacker could use this flaw to
    crash the system via a race condition triggered by setting certain ASCONF
    options on a socket. (CVE-2015-3212, Moderate)

    * An information leak flaw was found in the way the Linux kernel's Virtual
    Dynamic Shared Object (vDSO) implementation performed address
    randomization. A local, unprivileged user could use this flaw to leak
    kernel memory addresses to user-space. (CVE-2014-9585, Low)

    Red Hat would like to thank Canonical for reporting the CVE-2015-1333
    issue. The CVE-2015-0275 issue was discovered by Xiong Zhou of Red Hat, and
    the CVE-2015-3212 issue was discovered by Ji Jianwen of Red Hat
    Engineering.

    This update provides a build of the kernel-rt package for Red Hat
    Enterprise MRG 2.5 that is layered on Red Hat Enterprise Linux 6, and fixes
    the following issues:

    * Fix regression in scsi_send_eh_cmnd()

    * boot hangs at Console: switching to colour dummy device 80x25

    * Update tcp stack to 3.17 kernel

    * ksoftirqd high CPU usage due to stray tasklet from ioatdma driver

    (BZ#1245345)

    This update also fixes the following bugs:

    * The configuration option CONFIG_RTC_HCTOSYS was disabled on the realtime
    kernel causing the RTC clock to be adjusted with the UTC time even if the
    system is configured to set the RTC to the local time. By enabling the
    CONFIG_RTC_HCTOSYS configuration option, when the system is configured to
    use local time, RTC will correctly update with the local time and not try
    to use another timezone. (BZ#1248047)

    * In the realtime kernel, if a rt_mutex was taken while in interrupt
    context the normal priority inheritance protocol would falsely identify a
    deadlock and trigger a kernel crash. The patch that added the rt_mutex in
    this interrupt context was reverted. (BZ#1250649)

    All kernel-rt users are advised to upgrade to these updated packages, which
    correct these issues and add these enhancements. The system must be
    rebooted for this update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2015/rhsa-2015_1787.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f20fdf4");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2015:1787");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1181054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1193907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1226442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1239029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1245345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1245658");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9585");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-5366");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(401, 667, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/17");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list('CVE-2014-9585', 'CVE-2015-0275', 'CVE-2015-1333', 'CVE-2015-3212', 'CVE-2015-5364', 'CVE-2015-5366');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2015:1787');
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
      {'reference':'kernel-rt-3.10.0-229.rt56.161.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-debug-3.10.0-229.rt56.161.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-debug-devel-3.10.0-229.rt56.161.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-devel-3.10.0-229.rt56.161.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-doc-3.10.0-229.rt56.161.el6rt', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-firmware-3.10.0-229.rt56.161.el6rt', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-trace-3.10.0-229.rt56.161.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-trace-devel-3.10.0-229.rt56.161.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-vanilla-3.10.0-229.rt56.161.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'kernel-rt-vanilla-devel-3.10.0-229.rt56.161.el6rt', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rt', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'}
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
      severity   : SECURITY_NOTE,
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
