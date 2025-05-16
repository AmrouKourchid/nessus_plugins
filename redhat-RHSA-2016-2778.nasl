#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2778. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119385);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2016-8628");
  script_xref(name:"RHSA", value:"2016:2778");

  script_name(english:"RHEL 7 : atomic-openshift-utils (RHSA-2016:2778)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for atomic-openshift-utils.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2016:2778 advisory.

    Red Hat OpenShift Container Platform is the company's cloud computing Platform-as-a-Service (PaaS)
    solution designed for on-premise or private cloud deployments.

    Security Fix(es):

    * Ansible fails to properly sanitize fact variables sent from the Ansible controller. An attacker with the
    ability to create special variables on the controller could execute arbitrary commands on Ansible clients
    as the user Ansible runs as. (CVE-2016-8628)

    This issue was discovered by Michael Scherer (Red Hat).

    Bug Fix(es):

    * Previous versions of the openshift-ansible code base were not compatible with the latest Ansible 2.2.0.0
    release. This bug fix resolves several compatibility issues with the GA version of Ansible 2.2.0.0.
    (BZ#1389928) (BZ#1389275)

    * The hosts.ose.example inventory file had the incorrect openshift_release version set. This bug fix
    updates the version to match the channel in which it is shipped. (BZ#1386333)

    * The etcd certificate authority created by the installer had an expiry date one year in the future. With
    this bug fix, the expiry date has been updated to five years, matching the lifespan of other certificate
    authorities created by the installer. (BZ#1391548)

    * After restarting systemd-journal, master controllers and API services stopped working. This bug fix
    updates the installer to set Restart=always for the master controllers and API services, and this issue no
    longer occurs for new installations. For existing clusters, see
    https://access.redhat.com/solutions/2749571. (BZ#1378929)

    * When using the quick installer to install a cluster with a single master, the installer messaging
    suggested that an embedded etcd would be deployed. In newer versions of the quick installer, this is no
    longer the case, and a stand-alone etcd datastore is deployed in this scenario. This bug fix updates the
    quick installer messaging to match those changes. (BZ#1383961)

    * Upgrades would fail if the /etc/ansible/facts.d/openshift.fact cache was missing on the system,
    particularly for co-located master and etcd hosts. This bug fix improves etcd fact checking during
    upgrades, and the issue no longer occurs. (BZ#1391608)

    * Containerized upgrades from OpenShift Container Platform 3.2 to 3.3 would fail to properly create the
    service signing certificate due to an invalid path being used in containerized environments. This bug fix
    corrects that error, and containerized upgrades now create service signer certificates as a result.
    (BZ#1391865)

    * Upgrades from OpenShift Container Platform 3.2 to 3.3 could fail with the error
    AnsibleUndefinedVariable: 'dict object' has no attribute 'debug_level'. This bug fix sets missing
    defaults for debug_level, and as a result the upgrade error no longer occurs. (BZ#1392276)

    * Previously in embedded environments, etcd 2.x was used to backup the etcd data before performing an
    upgrade. However, etcd 2.x has a bug that prevents backups from working properly, preventing the upgrade
    playbooks from running to completion. With this bug fix, etcd 3.0 is now installed for embedded etcd
    environments, which resolves the bug allowing upgrades to proceed normally. This bug only presents itself
    when using the embedded etcd service on single master environments. (BZ#1382634)

    * Pacemaker clusters are no longer supported, but related code that remained could in some cases cause
    upgrade failures. This bug fix removes the Pacemaker restart logic from the installer to avoid these
    issues. (BZ#1382936)

    * Previously, upgrades from OpenShift Container Platform 3.1 to 3.2 could fail due to erroneous host names
    being added for etcd hosts during backup. This bug fix addresses issues with conditionals and loops in
    templates that caused this problem, and as a result the upgrade errors no longer occur. (BZ#1392169)

    All OpenShift Container Platform users are advised to upgrade to these updated packages.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2016/rhsa-2016_2778.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36174741");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:2778");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1378929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1382634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1382936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1383961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1386333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1388113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1389275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1389928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1391548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1391608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1391865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1392169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1392276");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL atomic-openshift-utils package based on the guidance in RHSA-2016:2778.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8628");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-callback-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-filter-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-lookup-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-playbooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-roles");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.2/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.2/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'atomic-openshift-utils-3.2.42-1.git.0.6b09be9.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-3.2.42-1.git.0.6b09be9.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-docs-3.2.42-1.git.0.6b09be9.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-filter-plugins-3.2.42-1.git.0.6b09be9.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-lookup-plugins-3.2.42-1.git.0.6b09be9.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-playbooks-3.2.42-1.git.0.6b09be9.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-roles-3.2.42-1.git.0.6b09be9.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.2/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.2/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.2/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ansible-2.2.0.0-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'atomic-openshift-utils-3.3.50-1.git.0.5bdbeaa.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-3.3.50-1.git.0.5bdbeaa.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-callback-plugins-3.3.50-1.git.0.5bdbeaa.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-docs-3.3.50-1.git.0.5bdbeaa.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-filter-plugins-3.3.50-1.git.0.5bdbeaa.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-lookup-plugins-3.3.50-1.git.0.5bdbeaa.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-playbooks-3.3.50-1.git.0.5bdbeaa.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-ansible-roles-3.3.50-1.git.0.5bdbeaa.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible / atomic-openshift-utils / openshift-ansible / etc');
}
