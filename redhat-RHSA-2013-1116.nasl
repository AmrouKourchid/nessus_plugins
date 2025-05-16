#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1116. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78966);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2013-2219");
  script_xref(name:"RHSA", value:"2013:1116");

  script_name(english:"RHEL 5 : redhat-ds-base (RHSA-2013:1116)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for redhat-ds-base.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2013:1116 advisory.

    Red Hat Directory Server is an LDAPv3 compliant server. The base packages
    include the Lightweight Directory Access Protocol (LDAP) server and
    command-line utilities for server administration.

    It was discovered that Red Hat Directory Server did not honor defined
    attribute access controls when evaluating search filter expressions. A
    remote attacker (with permission to query the Directory Server) could use
    this flaw to determine the values of restricted attributes via a series of
    search queries with filter conditions that used restricted attributes.
    (CVE-2013-2219)

    This issue was discovered by Ludwig Krispenz of Red Hat.

    This update also fixes the following bugs:

    * Prior to this update, the replication of the schema failed because of the
    attribute unhashed#user#password, which had an invalid name. When this
    problem happened, the error logs recorded the message Schema
    replication update failed: Invalid syntax. This update allows this
    attribute's name and the replication of the schema. (BZ#970934)

    * Prior to this update, under high load of incoming connections and due to
    a race condition, a connection which was not yet fully initialized could
    start being polled. This would lead to a crash. This update ensures that
    the connection is fully initialized before being in the polling set.
    (BZ#954051)

    * Prior to this update, if some requested attributes were skipped during a
    search (for example, because of an ACI), the returned attribute names and
    values could be shifted. This update removes attributes that are not
    authorized from the requested attributes set, so that the returned
    attributes/values are not shifted. (BZ#922773)

    * Prior to this update, when an attribute was configured to be encrypted,
    online import failed to store it in an encrypted way. This update allows
    encryption, on the consumer side, during an online import. (BZ#893178)

    * Prior to this update, updating the redhat-ds-base package resulted in the
    /etc/dirsrv/slapd-[instance]/certmap.conf file being overwritten with the
    default template. With this update, upgrading the redhat-ds-base package no
    longer causes /etc/dirsrv/slapd-[instance]/certmap.conf to be overwritten
    if the file already exists, preventing users from losing their custom
    changes. (BZ#919154)

    All users of Red Hat Directory Server 8.2 are advised to upgrade to these
    updated packages, which fix these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2013/rhsa-2013_1116.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7274761b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:1116");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=979508");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL redhat-ds-base package based on the guidance in RHSA-2013:1116.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2219");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-ds-base-devel");
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
      'content/dist/rhel/server/5/5Server/i386/directoryserver/8/os',
      'content/dist/rhel/server/5/5Server/i386/directoryserver/8/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/directoryserver/8/os',
      'content/dist/rhel/server/5/5Server/x86_64/directoryserver/8/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'redhat-ds-base-8.2.11-13.el5dsrv', 'cpu':'i386', 'release':'5', 'el_string':'el5dsrv', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'redhat-ds-base-8.2.11-13.el5dsrv', 'cpu':'x86_64', 'release':'5', 'el_string':'el5dsrv', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'redhat-ds-base-devel-8.2.11-13.el5dsrv', 'cpu':'i386', 'release':'5', 'el_string':'el5dsrv', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'redhat-ds-base-devel-8.2.11-13.el5dsrv', 'cpu':'x86_64', 'release':'5', 'el_string':'el5dsrv', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'redhat-ds-base / redhat-ds-base-devel');
}
