#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1449. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70553);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2013-0343",
    "CVE-2013-4299",
    "CVE-2013-4345",
    "CVE-2013-4368"
  );
  script_bugtraq_id(
    58795,
    62740,
    62935,
    63183
  );
  script_xref(name:"RHSA", value:"2013:1449");

  script_name(english:"RHEL 5 : kernel (RHSA-2013:1449)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2013:1449 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux
    operating system.

    * A flaw was found in the way the Linux kernel handled the creation of
    temporary IPv6 addresses. If the IPv6 privacy extension was enabled
    (/proc/sys/net/ipv6/conf/eth0/use_tempaddr is set to '2'), an attacker on
    the local network could disable IPv6 temporary address generation, leading
    to a potential information disclosure. (CVE-2013-0343, Moderate)

    * An information leak flaw was found in the way Linux kernel's device
    mapper subsystem, under certain conditions, interpreted data written to
    snapshot block devices. An attacker could use this flaw to read data from
    disk blocks in free space, which are normally inaccessible. (CVE-2013-4299,
    Moderate)

    * An off-by-one flaw was found in the way the ANSI CPRNG implementation in
    the Linux kernel processed non-block size aligned requests. This could lead
    to random numbers being generated with less bits of entropy than expected
    when ANSI CPRNG was used. (CVE-2013-4345, Moderate)

    * An information leak flaw was found in the way Xen hypervisor emulated the
    OUTS instruction for 64-bit paravirtualized guests. A privileged guest user
    could use this flaw to leak hypervisor stack memory to the guest.
    (CVE-2013-4368, Moderate)

    Red Hat would like to thank Fujitsu for reporting CVE-2013-4299, Stephan
    Mueller for reporting CVE-2013-4345, and the Xen project for reporting
    CVE-2013-4368.

    This update also fixes the following bug:

    * A bug in the GFS2 code prevented glock work queues from freeing
    glock-related memory while the glock memory shrinker repeatedly queued a
    large number of demote requests, for example when performing a simultaneous
    backup of several live GFS2 volumes with a large file count. As a
    consequence, the glock work queues became overloaded which resulted in a
    high CPU usage and the GFS2 file systems being unresponsive for a
    significant amount of time. A patch has been applied to alleviate this
    problem by calling the yield() function after scheduling a certain amount
    of tasks on the glock work queues. The problem can now occur only with
    extremely high work loads. (BZ#1014714)

    All kernel users are advised to upgrade to these updated packages, which
    contain backported patches to correct these issues. The system must be
    rebooted for this update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2013/rhsa-2013_1449.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d25a736");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:1449");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1004233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1007690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1012550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=914664");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2013:1449.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4299");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-4345");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(193);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "redhat_repos.nasl", "ssh_get_info.nasl");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '5')) audit(AUDIT_OS_NOT, 'Red Hat 5.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2013-0343', 'CVE-2013-4299', 'CVE-2013-4345', 'CVE-2013-4368');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2013:1449');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/5/5Client/i386/debug',
      'content/dist/rhel/client/5/5Client/i386/os',
      'content/dist/rhel/client/5/5Client/i386/source/SRPMS',
      'content/dist/rhel/client/5/5Client/x86_64/debug',
      'content/dist/rhel/client/5/5Client/x86_64/os',
      'content/dist/rhel/client/5/5Client/x86_64/source/SRPMS',
      'content/dist/rhel/power/5/5Server/ppc/debug',
      'content/dist/rhel/power/5/5Server/ppc/os',
      'content/dist/rhel/power/5/5Server/ppc/source/SRPMS',
      'content/dist/rhel/server/5/5Server/i386/debug',
      'content/dist/rhel/server/5/5Server/i386/os',
      'content/dist/rhel/server/5/5Server/i386/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/debug',
      'content/dist/rhel/server/5/5Server/x86_64/os',
      'content/dist/rhel/server/5/5Server/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/5/5Server/s390x/debug',
      'content/dist/rhel/system-z/5/5Server/s390x/os',
      'content/dist/rhel/system-z/5/5Server/s390x/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/i386/desktop/debug',
      'content/dist/rhel/workstation/5/5Client/i386/desktop/os',
      'content/dist/rhel/workstation/5/5Client/i386/desktop/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/x86_64/desktop/debug',
      'content/dist/rhel/workstation/5/5Client/x86_64/desktop/os',
      'content/dist/rhel/workstation/5/5Client/x86_64/desktop/source/SRPMS',
      'content/fastrack/rhel/client/5/i386/debug',
      'content/fastrack/rhel/client/5/i386/os',
      'content/fastrack/rhel/client/5/i386/source/SRPMS',
      'content/fastrack/rhel/client/5/x86_64/debug',
      'content/fastrack/rhel/client/5/x86_64/os',
      'content/fastrack/rhel/client/5/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/5/ppc/debug',
      'content/fastrack/rhel/power/5/ppc/os',
      'content/fastrack/rhel/power/5/ppc/source/SRPMS',
      'content/fastrack/rhel/server/5/i386/debug',
      'content/fastrack/rhel/server/5/i386/os',
      'content/fastrack/rhel/server/5/i386/source/SRPMS',
      'content/fastrack/rhel/server/5/x86_64/debug',
      'content/fastrack/rhel/server/5/x86_64/os',
      'content/fastrack/rhel/server/5/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/5/s390x/debug',
      'content/fastrack/rhel/system-z/5/s390x/os',
      'content/fastrack/rhel/system-z/5/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/5/i386/desktop/debug',
      'content/fastrack/rhel/workstation/5/i386/desktop/os',
      'content/fastrack/rhel/workstation/5/i386/desktop/source/SRPMS',
      'content/fastrack/rhel/workstation/5/x86_64/desktop/debug',
      'content/fastrack/rhel/workstation/5/x86_64/desktop/os',
      'content/fastrack/rhel/workstation/5/x86_64/desktop/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-2.6.18-371.1.2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.18-371.1.2.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.18-371.1.2.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.18-371.1.2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.18-371.1.2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.18-371.1.2.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.18-371.1.2.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.18-371.1.2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.18-371.1.2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.18-371.1.2.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.18-371.1.2.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.18-371.1.2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.18-371.1.2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.18-371.1.2.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.18-371.1.2.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.18-371.1.2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.18-371.1.2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.18-371.1.2.el5', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.18-371.1.2.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.18-371.1.2.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.18-371.1.2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-2.6.18-371.1.2.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-2.6.18-371.1.2.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-2.6.18-371.1.2.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-2.6.18-371.1.2.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-PAE-2.6.18-371.1.2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-PAE-devel-2.6.18-371.1.2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xen-2.6.18-371.1.2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xen-2.6.18-371.1.2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xen-devel-2.6.18-371.1.2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xen-devel-2.6.18-371.1.2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-PAE / kernel-PAE-devel / kernel-debug / etc');
}
