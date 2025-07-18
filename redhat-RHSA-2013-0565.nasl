#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0565. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76657);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2012-4462");
  script_bugtraq_id(58336);
  script_xref(name:"RHSA", value:"2013:0565");

  script_name(english:"RHEL 6 : Red Hat Enterprise MRG Grid 2.3 (RHSA-2013:0565)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for Red Hat Enterprise MRG Grid 2.3.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2013:0565 advisory.

    Red Hat Enterprise MRG (Messaging, Realtime, and Grid) is a next-generation
    IT infrastructure for enterprise computing. MRG offers increased
    performance, reliability, interoperability, and faster computing for
    enterprise customers.

    MRG Grid provides high-throughput computing and enables enterprises to
    achieve higher peak computing capacity as well as improved infrastructure
    utilization by leveraging their existing technology to build high
    performance grids. MRG Grid provides a job-queueing mechanism, scheduling
    policy, and a priority scheme, as well as resource monitoring and resource
    management. Users submit their jobs to MRG Grid, where they are placed into
    a queue. MRG Grid then chooses when and where to run the jobs based upon a
    policy, carefully monitors their progress, and ultimately informs the user
    upon completion.

    It was found that attempting to remove a job via
    /usr/share/condor/aviary/jobcontrol.py with CPROC in square brackets
    caused condor_schedd to crash. If aviary_query_server was configured to
    listen to public interfaces, this could allow a remote attacker to cause a
    denial of service condition in condor_schedd. While condor_schedd was
    restarted by the condor_master process after each exit, condor_master would
    throttle back restarts after each crash. This would slowly increment to the
    defined MASTER_BACKOFF_CEILING value (3600 seconds/1 hour, by default).
    (CVE-2012-4462)

    The CVE-2012-4462 issue was discovered by Daniel Horak of the Red Hat
    Enterprise MRG Quality Engineering Team.

    These updated packages for Red Hat Enterprise Linux 6 provide numerous
    enhancements and bug fixes for the Grid component of MRG. Some of the most
    important enhancements include:

    * Release of HTCondor 7.8
    * OS integration with control groups (cgroups)
    * Kerberos integration and HTML5 interactivity in the management console
    * Historical data reporting in the management console as Technology Preview
    * Job data availability from MongoDB as Technology Preview
    * Updated EC2 AMI and instance tagging support
    * Enhanced negotiation and accounting
    * Enhanced DAG workflow management
    * Enhancements to configuration inspection, node inventory, and
    configuration of walk-in or dynamic resources
    * High availability for Aviary

    Space precludes documenting all of these changes in this advisory. Refer to
    the Red Hat Enterprise MRG 2 Technical Notes document, available shortly
    from the link in the References section, for information on these changes.

    All users of the Grid capabilities of Red Hat Enterprise MRG are advised
    to upgrade to these updated packages, which correct this issue, and fix
    the bugs and add the enhancements noted in the Red Hat Enterprise MRG 2
    Technical Notes.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_MRG/2/html/Technical_Notes/RHSA-2013-0565.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abd288b5");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2013/rhsa-2013_0565.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc2c1e22");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:0565");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#low");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=860850");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat Enterprise MRG Grid 2.3 package based on the guidance in RHSA-2013:0565.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4462");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-aviary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-classads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-cluster-resource-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-deltacloud-gahp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-ec2-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-ec2-enhanced-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-job-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-kbdd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-low-latency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-plumage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-vm-gahp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-base-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-wallaby-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cumin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:deltacloud-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:deltacloud-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:deltacloud-core-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-condorec2e");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-condorutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wallabyclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-condor-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-rhubarb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-spqr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sesame");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spqr-gen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wallaby-utils");
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
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/mrg-g-execute/2/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/mrg-g-execute/2/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/mrg-g-execute/2/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/mrg-mgmt/2/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/mrg-mgmt/2/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/mrg-mgmt/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-g-execute/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-g-execute/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-g-execute/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-g/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-g/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-g/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-m/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-m/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-m/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-mgmt/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-mgmt/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-mgmt/2/source/SRPMS',
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
      {'reference':'condor-7.8.8-0.4.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-7.8.8-0.4.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-aviary-7.8.8-0.4.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-aviary-7.8.8-0.4.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-classads-7.8.8-0.4.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-classads-7.8.8-0.4.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-cluster-resource-agent-7.8.8-0.4.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-cluster-resource-agent-7.8.8-0.4.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-deltacloud-gahp-7.8.8-0.4.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-job-hooks-1.5-6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-kbdd-7.8.8-0.4.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-kbdd-7.8.8-0.4.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-low-latency-1.2-3.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-plumage-7.8.8-0.4.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-plumage-7.8.8-0.4.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-qmf-7.8.8-0.4.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-qmf-7.8.8-0.4.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-vm-gahp-7.8.8-0.4.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-wallaby-base-db-1.25-1.el6_3', 'release':'6', 'el_string':'el6_3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-wallaby-client-5.0.5-2.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-wallaby-tools-5.0.5-2.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'python-condorutils-1.5-6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'python-wallaby-0.16.3-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'python-wallabyclient-5.0.5-2.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'ruby-condor-wallaby-5.0.5-2.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'ruby-rhubarb-0.4.3-5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'ruby-spqr-0.3.6-3.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'ruby-wallaby-0.16.3-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'sesame-1.0-8.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'sesame-1.0-8.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'spqr-gen-0.3.6-3.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'wallaby-0.16.3-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'wallaby-utils-0.16.3-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/mrg-g-execute/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-g-execute/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-g-execute/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-g/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-g/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-g/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-m/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-m/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-m/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-mgmt/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-mgmt/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-mgmt/2/source/SRPMS',
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
      {'reference':'condor-ec2-enhanced-1.3.0-2.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-ec2-enhanced-hooks-1.3.0-3.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'cumin-0.1.5675-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'deltacloud-core-0.5.0-11.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'deltacloud-core-doc-0.5.0-11.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'deltacloud-core-rhevm-0.5.0-11.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'python-condorec2e-1.3.0-3.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'ruby-nokogiri-1.5.0-0.9.beta4.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-nokogiri-1.5.0-0.9.beta4.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-nokogiri-doc-1.5.0-0.9.beta4.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-rack-1.3.0-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'condor / condor-aviary / condor-classads / etc');
}
