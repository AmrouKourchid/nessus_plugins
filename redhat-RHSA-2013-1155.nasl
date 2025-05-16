#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1155. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78968);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2013-4236");
  script_xref(name:"RHSA", value:"2013:1155");

  script_name(english:"RHEL 6 : rhev 3.2.2 - vdsm (RHSA-2013:1155)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for rhev 3.2.2 - vdsm.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2013:1155 advisory.

    VDSM is a management module that serves as a Red Hat Enterprise
    Virtualization Manager agent on Red Hat Enterprise Virtualization
    Hypervisor or Red Hat Enterprise Linux hosts.

    It was found that the fix for CVE-2013-0167 released via RHSA-2013:0886
    was incomplete. A privileged guest user could potentially use this flaw to
    make the host the guest is running on unavailable to the management
    server. (CVE-2013-4236)

    This issue was found by David Gibson of Red Hat.

    This update also fixes the following bugs:

    * Previously, failure to move a disk produced a 'truesize' exit message,
    which was not informative. Now, failure to move a disk produces a more
    helpful error message explaining that the volume is corrupted or missing.
    (BZ#985556)

    * The LVM filter has been updated to only access physical volumes by full
    /dev/mapper paths in order to improve performance. This replaces the
    previous behavior of scanning all devices including logical volumes on
    physical volumes. (BZ#983599)

    * The log collector now collects /var/log/sanlock.log from Hypervisors, to
    assist in debugging sanlock errors. (BZ#987042)

    * When the poollist parameter was not defined, dumpStorageTable crashed,
    causing SOS report generation to fail with the error 'IndexError: list
    index out of range'. VDSM now handles this exception, so the log collector
    can generate host SOS reports. (BZ#985069)

    * Previously, VDSM used the memAvailable parameter to report available
    memory on a host, which could return negative values if memory
    overcommitment was in use. Now, the new memFree parameter returns the
    actual amount of free memory on a host. (BZ#982639)

    All users managing Red Hat Enterprise Linux Virtualization hosts using Red
    Hat Enterprise Virtualization Manager are advised to install these updated
    packages, which fix these issues.

    These updated packages will be provided to users of Red Hat Enterprise
    Virtualization Hypervisor in the next rhev-hypervisor6 errata package.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2013/rhsa-2013_1155.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?857c3032");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:1155");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=982639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=983599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=985556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=987042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=996166");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHSA-2013-0886.html");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL rhev 3.2.2 - vdsm package based on the guidance in RHSA-2013:1155.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4236");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-vhostmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-reg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

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

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/x86_64/rhev-agent/3/debug',
      'content/dist/rhel/client/6/6Client/x86_64/rhev-agent/3/os',
      'content/dist/rhel/client/6/6Client/x86_64/rhev-agent/3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-agent/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-agent/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-agent/3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-mgmt-agent/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-mgmt-agent/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-mgmt-agent/3/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhev-agent/3/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhev-agent/3/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhev-agent/3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'vdsm-4.10.2-24.0.el6ev', 'cpu':'x86_64', 'release':'6', 'el_string':'el6ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'},
      {'reference':'vdsm-cli-4.10.2-24.0.el6ev', 'release':'6', 'el_string':'el6ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'},
      {'reference':'vdsm-hook-vhostmd-4.10.2-24.0.el6ev', 'release':'6', 'el_string':'el6ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'},
      {'reference':'vdsm-python-4.10.2-24.0.el6ev', 'cpu':'x86_64', 'release':'6', 'el_string':'el6ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'},
      {'reference':'vdsm-reg-4.10.2-24.0.el6ev', 'release':'6', 'el_string':'el6ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'},
      {'reference':'vdsm-xmlrpc-4.10.2-24.0.el6ev', 'release':'6', 'el_string':'el6ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'vdsm / vdsm-cli / vdsm-hook-vhostmd / vdsm-python / vdsm-reg / etc');
}
