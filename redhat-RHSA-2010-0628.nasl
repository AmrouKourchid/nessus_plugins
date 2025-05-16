#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0628. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79277);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/03");

  script_cve_id("CVE-2010-2811");
  script_bugtraq_id(42580);
  script_xref(name:"RHSA", value:"2010:0628");

  script_name(english:"RHEL 5 : vdsm22 (RHSA-2010:0628)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for vdsm22.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2010:0628 advisory.

    VDSM is a management module that serves as a Red Hat Enterprise
    Virtualization Manager agent on Red Hat Enterprise Virtualization
    Hypervisor or Red Hat Enterprise Linux hosts.

    Note: This update has been tested and is supported on Red Hat Enterprise
    Linux 5.5 (with all appropriate post-GA 5.5-specific updates).

    A flaw was found in the way VDSM accepted SSL connections. An attacker
    could trigger this flaw by creating a crafted SSL connection to VDSM,
    preventing VDSM from accepting SSL connections from other users.
    (CVE-2010-2811)

    These updated vdsm22 packages also fix the following bugs:

    * suspend-to-file hibernation failed for huge guests due to the migration
    and hibernation constant values being too short for huge guests. This
    update makes the timeouts proportional to guest RAM size, thus allowing
    suspension of huge guests in all cases except where storage is unbearably
    slow. (BZ#601275)

    * under certain circumstances, restarting a VDSM that was being used as a
    Storage Pool Manager killed all system processes on the host. With this
    update, stopping VDSM is ensured to kill only the processes that it
    started, and the VDSM SIGTERM handler is not run concurrently. With these
    changes, all processes on the host are no longer killed when VDSM is
    restarted. (BZ#614849)

    * when VDSM was requested to start in paused mode, it incorrectly
    reported virtual guest state as WaitForLaunch instead of Paused, which
    led to the virtual guest being inaccessible from Red Hat Enterprise
    Virtualization Manager. With this update, VDSM reports such virtual guests
    as Paused, and users are able to connect to the virtual guest display.
    (BZ#616464)

    Red Hat Enterprise Virtualization Manager 2.2 users with Red Hat Enterprise
    Linux hosts should install these updated packages, which resolve these
    issues. Alternatively, Red Hat Enterprise Virtualization Manager can
    install the new package automatically.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2010/rhsa-2010_0628.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae137b9c");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=622928");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0628");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL vdsm22 package based on the guidance in RHSA-2010:0628.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-2811");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm22-cli");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '5')) audit(AUDIT_OS_NOT, 'Red Hat 5.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/5/5Client/x86_64/rhev-agent/3/os',
      'content/dist/rhel/client/5/5Client/x86_64/rhev-agent/3/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/rhev-agent/3/os',
      'content/dist/rhel/server/5/5Server/x86_64/rhev-agent/3/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/rhev-mgmt-agent/3/os',
      'content/dist/rhel/server/5/5Server/x86_64/rhev-mgmt-agent/3/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/rhv-agent/4/debug',
      'content/dist/rhel/server/5/5Server/x86_64/rhv-agent/4/os',
      'content/dist/rhel/server/5/5Server/x86_64/rhv-agent/4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'vdsm22-4.5-62.14.el5_5rhev2_2', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_5rhev2_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'},
      {'reference':'vdsm22-cli-4.5-62.14.el5_5rhev2_2', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_5rhev2_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'vdsm22 / vdsm22-cli');
}
