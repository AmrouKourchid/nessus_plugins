#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:7851. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194386);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2023-4886",
    "CVE-2023-28362",
    "CVE-2023-41040",
    "CVE-2023-43804",
    "CVE-2023-45803"
  );
  script_xref(name:"RHSA", value:"2023:7851");

  script_name(english:"RHEL 8 : Satellite 6.14.1 Async Security Update (Moderate) (RHSA-2023:7851)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:7851 advisory.

    Red Hat Satellite is a system management solution that allows organizations
    to configure and maintain their systems without the necessity to provide
    public Internet access to their servers or other client systems. It
    performs provisioning and configuration management of predefined standard
    operating environments.

    Security fix(es):

    * rubygem-actionpack: actionpack: Possible XSS via User Supplied Values to redirect_to
    [rhn_satellite_6.14] (CVE-2023-28362)

    * foreman: World readable file containing secrets [rhn_satellite_6.14] (CVE-2023-4886)

    * python-urllib3: urllib3: Request body not stripped after redirect from 303 status changes request method
    to GET [rhn_satellite_6-default] (CVE-2023-45803 )

    *  python-gitpython: GitPython: Blind local file inclusion [rhn_satellite_6-default] (CVE-2023-41040)

    This update fixes the following bugs:

    2250342 - REX job finished with exit code 0 but the script failed on client side due to no space.
    2250343 - Selinux denials are reported after following Chapter 13. Managing Custom File Type Content
    chapter step by step
    2250344 - Long running postgres threads during content-export
    2250345 - Upgrade django-import-export package to at least 3.1.0
    2250349 - After upstream repo switched to zst compression, Satellite 6.12.5.1 unable to sync
    2250350 - Slow generate applicability for Hosts with multiple modulestreams installed
    2250352 - Recalculate button for Errata is not available on Satellite 6.13/ Satellite 6.14 if no errata is
    present
    2250351 - Actions::ForemanLeapp::PreupgradeJob fails with null value in column preupgrade_report_id
    violates not-null constraint when run with non-admin user
    2251799 - REX Template for 'convert2rhel analyze' command
    2254085 - Getting '/usr/sbin/foreman-rake db:migrate' returned 1 instead of one of [0] ERROR while trying
    to upgrade Satellite 6.13 to 6.14
    2254080 - satellite-convert2rhel-toolkit rpm v1.0.0 in 6.14.z

    Users of Red Hat Satellite are advised to upgrade to these updated
    packages, which fix these bugs.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  # https://access.redhat.com/documentation/en-us/red_hat_satellite/6.14/html/upgrading_red_hat_satellite_to_6.14/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?662f0b0b");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_7851.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a52677ca");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2217785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2230135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2246840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250352");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2251799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254085");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:7851");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-43804");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 200);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-dynflow-sidekiq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-telemetry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulpcore-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django-import-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gitpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulpcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-django-import-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-gitpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-pulp-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-pulpcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actioncable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actionmailbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actiontext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actionview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activejob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activestorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_leapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_remote_execution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_remote_execution-cockpit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-railties");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_remote_execution_ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-capsule");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-convert2rhel-toolkit");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.14/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.14/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.14/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.14/debug',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.14/os',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.14/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.14/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.14/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.14/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'foreman-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-cli-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-debug-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-dynflow-sidekiq-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-ec2-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-journald-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-libvirt-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-openstack-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-ovirt-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-postgresql-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-redis-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-service-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-telemetry-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-vmware-3.7.0.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'satellite-6.14.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'satellite-capsule-6.14.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'satellite-cli-6.14.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'satellite-common-6.14.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.14/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.14/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.14/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.14/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.14/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.14/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'createrepo_c-1.0.2-2.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'createrepo_c-libs-1.0.2-2.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'foreman-installer-3.7.0.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'foreman-installer-katello-3.7.0.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2023-4886', 'CVE-2023-43804']},
      {'reference':'pulpcore-selinux-2.0.0-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'python3-createrepo_c-1.0.2-2.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'python39-createrepo_c-1.0.2-2.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'python39-django-import-export-3.1.0-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'python39-gitpython-3.1.40-0.1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-41040', 'CVE-2023-43804']},
      {'reference':'python39-pulp-rpm-3.19.11-2.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'python39-pulpcore-3.22.19-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'python39-urllib3-1.26.18-0.1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804', 'CVE-2023-45803']},
      {'reference':'rubygem-smart_proxy_remote_execution_ssh-0.10.2-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/satellite/6.14/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.14/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.14/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-actioncable-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-actionmailbox-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-actionmailer-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-actionpack-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-28362', 'CVE-2023-43804']},
      {'reference':'rubygem-actiontext-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-actionview-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-activejob-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-activemodel-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-activerecord-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-activestorage-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-activesupport-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-foreman_leapp-1.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-foreman_remote_execution-10.1.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-foreman_remote_execution-cockpit-10.1.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-katello-4.9.0.18-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-rails-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'rubygem-railties-6.1.7.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']},
      {'reference':'satellite-convert2rhel-toolkit-1.0.0-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2023-43804']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'createrepo_c / createrepo_c-libs / foreman / foreman-cli / etc');
}
