#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0704. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49639);
  script_version("1.42");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/21");

  script_cve_id("CVE-2010-3081");
  script_bugtraq_id(43239);
  script_xref(name:"RHSA", value:"2010:0704");

  script_name(english:"RHEL 5 : kernel (RHSA-2010:0704)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2010:0704 advisory.

  - kernel: 64-bit Compatibility Mode Stack Pointer Underflow (CVE-2010-3081)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2010/rhsa-2010_0704.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fd056ea");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0704");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/kb/docs/DOC-40265");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=634457");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2010:0704.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3081");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/22");

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

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '5')) audit(AUDIT_OS_NOT, 'Red Hat 5.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2010-3081');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2010:0704');
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
      {'reference':'kernel-2.6.18-194.11.4.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.18-194.11.4.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.18-194.11.4.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.18-194.11.4.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.18-194.11.4.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.18-194.11.4.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.18-194.11.4.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.18-194.11.4.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.18-194.11.4.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.18-194.11.4.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.18-194.11.4.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.18-194.11.4.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.18-194.11.4.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.18-194.11.4.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.18-194.11.4.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.18-194.11.4.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.18-194.11.4.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.18-194.11.4.el5', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.18-194.11.4.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.18-194.11.4.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.18-194.11.4.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-2.6.18-194.11.4.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-2.6.18-194.11.4.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-2.6.18-194.11.4.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-2.6.18-194.11.4.el5', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-PAE-2.6.18-194.11.4.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-PAE-devel-2.6.18-194.11.4.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xen-2.6.18-194.11.4.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xen-2.6.18-194.11.4.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xen-devel-2.6.18-194.11.4.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xen-devel-2.6.18-194.11.4.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-PAE / kernel-PAE-devel / kernel-debug / etc');
}
