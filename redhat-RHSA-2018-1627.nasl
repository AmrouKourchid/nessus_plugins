#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:1627. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194093);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id("CVE-2017-12155", "CVE-2018-1000115");
  script_xref(name:"RHSA", value:"2018:1627");

  script_name(english:"RHEL 7 : Red Hat OpenStack Platform director (RHSA-2018:1627)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat OpenStack Platform director.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2018:1627 advisory.

    Red Hat OpenStack Platform director provides the facilities for deploying
    and monitoring a private or public infrastructure-as-a-service (IaaS) cloud
    based on Red Hat OpenStack Platform.

    Security Fix(es):

    * A resource-permission flaw was found in the python-tripleo and openstack-tripleo-heat-templates packages
    where ceph.client.openstack.keyring is created as world-readable. A local attacker with access to the key
    could read or modify data on Ceph cluster pools for OpenStack as though the attacker were the OpenStack
    service, thus potentially reading or modifying data in an OpenStack Block Storage volume.

    To exploit this flaw, the attacker must have local access to an overcloud node. However by default, access
    to overcloud nodes is restricted and accessible only from the management undercloud server on an internal
    network. (CVE-2017-12155)

    This issue was discovered by Katuya Kawakami (NEC).

    * It was discovered that the memcached connections using UDP transport protocol can be abused for
    efficient traffic amplification distributed denial of service (DDoS) attacks. A remote attacker could send
    a malicious UDP request using a spoofed source IP address of a target system to memcached, causing it to
    send a significantly larger response to the target. (CVE-2018-1000115)

    This update also includes the following bug fixes and enhancements:

    * Prior to this update, when removing the ceph-osd RPM from overcloud nodes that do not require the
    package, the corresponding Ceph OSD product key was not removed. Consequently, the subscription-manager
    would incorrectly report that the Ceph OSD product was still installed.
    With this update, the script that handles removal of the ceph-osd RPM now also removes the Ceph OSD
    product key. Note: The script that removes the RPM and product key executes only during the overcloud
    update procedure; the product key is removed only when the overcloud node is updated.
    As a result, after removing the ceph-osd RPM, the subscription-manager no longer reports the Ceph OSD
    product is installed. (BZ#1571436)

    * Previously, there were errors in the director Heat template that configures the VMAX Cinder backend
    driver. Consequently, the VMAX driver would not function correctly. With this update, the errors have been
    corrected, and the VMAX driver functions correctly. (BZ#1546799)

    * This enhancement adds director support for deploying the Dell EMC VMAX cinder backend. (BZ#1546793)

    * In this enhancement, if a minor update is blocked by an existing yum process that prevents the package
    update, the process should exit with an appropriate error message. This was added because the minor update
    may appear to freeze, due to yum waiting for the existing yum.pid to exit; when it eventually fails it is
    not immediately clear why. As a result, if there is an existing yum process preventing the package update,
    then the minor update fails with a clear message to indicate this: ERROR existing yum.pid detected -
    can't continue! Please ensure there is no other package update process for the duration of the minor
    update worfklow. Exiting. (BZ#1471721)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1445766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1471721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1478274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1489360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1518009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1524422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1546799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1547089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1547956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1548345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1550167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1551182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1552245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1567349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1567365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1571436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1577957");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2018/rhsa-2018_1627.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e694de26");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:1627");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat OpenStack Platform director package based on the guidance in RHSA-2018:1627.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12155");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(732);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-tripleo-heat-templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-tripleo");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/11/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/11/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/11/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/11/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/11/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/11/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/11/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/11/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/11/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/11/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/11/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/11/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/11/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/11/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/11/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openstack-tripleo-heat-templates-6.2.12-2.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'puppet-tripleo-6.5.10-3.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openstack-tripleo-heat-templates / puppet-tripleo');
}
