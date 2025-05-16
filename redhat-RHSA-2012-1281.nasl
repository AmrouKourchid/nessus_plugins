#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1281. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76651);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/20");

  script_cve_id(
    "CVE-2012-2680",
    "CVE-2012-2681",
    "CVE-2012-2683",
    "CVE-2012-2684",
    "CVE-2012-2685",
    "CVE-2012-2734",
    "CVE-2012-2735",
    "CVE-2012-3459",
    "CVE-2012-3491",
    "CVE-2012-3492",
    "CVE-2012-3493"
  );
  script_bugtraq_id(55632);
  script_xref(name:"RHSA", value:"2012:1281");

  script_name(english:"RHEL 6 : Red Hat Enterprise MRG Grid 2.2 (RHSA-2012:1281)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat Enterprise MRG Grid 2.2.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2012:1281 advisory.

    Red Hat Enterprise MRG (Messaging, Realtime, and Grid) is a next-generation
    IT infrastructure for enterprise computing. MRG offers increased
    performance, reliability, interoperability, and faster computing for
    enterprise customers.

    A number of unprotected resources (web pages, export functionality, image
    viewing) were found in Cumin. An unauthenticated user could bypass intended
    access restrictions, resulting in information disclosure. (CVE-2012-2680)

    Cumin could generate weak session keys, potentially allowing remote
    attackers to predict session keys and obtain unauthorized access to Cumin.
    (CVE-2012-2681)

    Multiple cross-site scripting flaws in Cumin could allow remote attackers
    to inject arbitrary web script on a web page displayed by Cumin.
    (CVE-2012-2683)

    An SQL injection flaw in Cumin could allow remote attackers to manipulate
    the contents of the back-end database via a specially-crafted URL.
    (CVE-2012-2684)

    When Cumin handled image requests, clients could request images of
    arbitrary sizes. This could result in large memory allocations on the Cumin
    server, leading to an out-of-memory condition. (CVE-2012-2685)

    Cumin did not protect against Cross-Site Request Forgery attacks. If an
    attacker could trick a user, who was logged into the Cumin web interface,
    into visiting a specially-crafted web page, it could lead to unauthorized
    command execution in the Cumin web interface with the privileges of the
    logged-in user. (CVE-2012-2734)

    A session fixation flaw was found in Cumin. An authenticated user able to
    pre-set the Cumin session cookie in a victim's browser could possibly use
    this flaw to steal the victim's session after they log into Cumin.
    (CVE-2012-2735)

    It was found that authenticated users could send a specially-crafted HTTP
    POST request to Cumin that would cause it to submit a job attribute change
    to Condor. This could be used to change internal Condor attributes,
    including the Owner attribute, which could allow Cumin users to elevate
    their privileges. (CVE-2012-3459)

    It was discovered that Condor's file system authentication challenge
    accepted directories with weak permissions (for example, world readable,
    writable and executable permissions). If a user created a directory with
    such permissions, a local attacker could rename it, allowing them to
    execute jobs with the privileges of the victim user. (CVE-2012-3492)

    It was discovered that Condor exposed private information in the data in
    the ClassAds format served by condor_startd. An unauthenticated user able
    to connect to condor_startd's port could request a ClassAd for a running
    job, provided they could guess or brute-force the PID of the job. This
    could expose the ClaimId which, if obtained, could be used to control the
    job as well as start new jobs on the system. (CVE-2012-3493)

    It was discovered that the ability to abort a job in Condor only required
    WRITE authorization, instead of a combination of WRITE authorization and
    job ownership. This could allow an authenticated attacker to bypass
    intended restrictions and abort any idle job on the system. (CVE-2012-3491)

    The above issues were discovered by Florian Weimer of the Red Hat Product
    Security Team.

    This update also provides defense in depth patches for Condor. (BZ#848212,
    BZ#835592, BZ#841173, BZ#843476)

    These updated packages for Red Hat Enterprise Linux 6 provide numerous
    enhancements and bug fixes for the Grid component of MRG. Some highlights
    include:

    * Integration with Red Hat Enterprise Virtualization Manager via Deltacloud
    * Role enforcement in Cumin
    * Cumin authentication integration with LDAP
    * Enhanced Red Hat HA integration managing multiple-schedulers nodes
    * Generic local resource limits for partitionable slots
    * Concurrency limit groups

    Space precludes documenting all of these changes in this advisory. Refer to
    the Red Hat Enterprise MRG 2 Technical Notes document, linked to in the
    References section, for information on these changes.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2012/rhsa-2012_1281.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b6048d0");
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_MRG/2/html/Technical_Notes/sec-Red_Hat_Enterprise_Linux_6.html#RHSA-2012-1281
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d4e1de3");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2012:1281");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=827558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=828434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=829421");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=830243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=830245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=830248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=832124");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=832151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=846501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=848212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=848214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=848218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=848222");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat Enterprise MRG Grid 2.2 package based on the guidance in RHSA-2012:1281.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2684");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2012-2734");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352, 384, 79);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-aviary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-classads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-cluster-resource-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-deltacloud-gahp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:condor-kbdd");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdeltacloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdeltacloud-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wallabyclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-hpricot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-wallaby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-eventmachine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fssm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-haml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hpricot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hpricot-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-maruku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mime-types-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mocha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-ssh-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-accept");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-accept-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sass-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sinatra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-syntax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-thin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-thin-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tilt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-yard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sesame");
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
      {'reference':'condor-7.6.5-0.22.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-7.6.5-0.22.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-aviary-7.6.5-0.22.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-aviary-7.6.5-0.22.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-classads-7.6.5-0.22.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-classads-7.6.5-0.22.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-cluster-resource-agent-7.6.5-0.22.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-cluster-resource-agent-7.6.5-0.22.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-deltacloud-gahp-7.6.5-0.22.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-kbdd-7.6.5-0.22.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-kbdd-7.6.5-0.22.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-plumage-7.6.5-0.22.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-plumage-7.6.5-0.22.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-qmf-7.6.5-0.22.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-qmf-7.6.5-0.22.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-vm-gahp-7.6.5-0.22.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-wallaby-base-db-1.23-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-wallaby-client-4.1.3-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'condor-wallaby-tools-4.1.3-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'python-wallaby-0.12.5-10.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'python-wallabyclient-4.1.3-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'ruby-wallaby-0.12.5-10.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-rake-0.8.7-2.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygems-1.8.16-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'sesame-1.0-6.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'sesame-1.0-6.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'wallaby-0.12.5-10.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'wallaby-utils-0.12.5-10.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'}
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
      {'reference':'cumin-0.1.5444-3.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'deltacloud-core-0.5.0-10.el6_2', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'deltacloud-core-doc-0.5.0-10.el6_2', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'deltacloud-core-rhevm-0.5.0-10.el6_2', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'libdeltacloud-0.9-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'libdeltacloud-devel-0.9-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'ruby-hpricot-0.8.4-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'ruby-json-1.4.6-10.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'ruby-nokogiri-1.5.0-0.8.beta4.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-daemons-1.1.4-2.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-eventmachine-0.12.10-7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-fssm-0.2.7-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-haml-3.1.2-2.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-hpricot-0.8.4-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-hpricot-doc-0.8.4-2.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-json-1.4.6-10.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-maruku-0.6.0-4.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-mime-types-1.16-4.el6_0', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-mime-types-doc-1.16-4.el6_0', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-mocha-0.9.7-4.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-net-ssh-2.0.23-6.el6_0', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-net-ssh-doc-2.0.23-6.el6_0', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-nokogiri-1.5.0-0.8.beta4.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-nokogiri-doc-1.5.0-0.8.beta4.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-rack-1.3.0-2.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'rubygem-rack-accept-0.4.3-6.el6_0', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-rack-accept-doc-0.4.3-6.el6_0', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-rack-test-0.6.1-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-rest-client-1.6.1-2.el6_0', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-sass-3.1.4-4.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-sass-doc-3.1.4-4.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-sinatra-1.2.6-2.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'mrg-release'},
      {'reference':'rubygem-syntax-1.0.0-4.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-thin-1.2.11-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-thin-doc-1.2.11-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-tilt-1.3.2-3.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-tilt-doc-1.3.2-3.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'rubygem-yard-0.7.2-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'condor / condor-aviary / condor-classads / etc');
}
