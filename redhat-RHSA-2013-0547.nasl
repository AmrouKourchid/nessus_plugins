#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0547. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210166);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2012-5561", "CVE-2012-6116");
  script_xref(name:"RHSA", value:"2013:0547");

  script_name(english:"RHEL 6 : CloudForms System Engine 1.1.2 update (Moderate) (RHSA-2013:0547)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2013:0547 advisory.

    Red Hat CloudForms is an on-premise hybrid cloud
    Infrastructure-as-a-Service (IaaS) product that lets you create and manage
    private and public clouds. It provides self-service computing resources to
    users in a managed, governed, and secure way. CloudForms System Engine can
    be used to configure new systems, subscribe to updates, and maintain
    installations in distributed environments.

    It was found that the
    /usr/share/katello/script/katello-generate-passphrase utility, which is
    run during the installation and configuration process, set world-readable
    permissions on the /etc/katello/secure/passphrase file. A local attacker
    could use this flaw to obtain the passphrase for Katello, giving them
    access to information they would otherwise not have access to.
    (CVE-2012-5561)

    Note: After installing this update, ensure the
    /etc/katello/secure/passphrase file is owned by the root user and group
    and mode 0750 permissions. Sites should also consider re-creating the
    Katello passphrase as this issue exposed it to local users.

    One task the katello-configure utility performs is creating an RPM to be
    installed on client machines that need to connect to the Katello server. It
    was found that this RPM set world-readable and writable permissions on the
    pem file (containing the Certificate Authority certificate) used for
    trusting the Katello server. An attacker could use this flaw to perform a
    man-in-the-middle attack, allowing them to manage (such as installing and
    removing software) Katello client systems. (CVE-2012-6116)

    The CVE-2012-5561 issue was discovered by Aaron Weitekamp of the Red Hat
    Cloud Quality Engineering team, and CVE-2012-6116 was discovered by Dominic
    Cleal and James Laska of Red Hat.

    This update also fixes the following bugs:

    * The CloudForms System Engine command line tool incorrectly parsed
    locales, which caused the following error:

    translation missing: de.activerecord.errors.messages.record_invalid

    This update replaces the controller for setting the locale. The translation
    error no longer appears. (BZ#896251)

    * Certain locales did not properly escape certain UI content for new role
    creation. This broke the Save button for some locales. This update corrects
    the escape behavior for localized UI content. The Save button now works
    for new role creation. (BZ#896252)

    * A missing icon stopped users from deleting recent or saved searches. This
    update adds the icon and users can now delete recent or saved searches.
    (BZ#896253)

    * A performance issue in the Candlepin 0.7.8 component caused subscription
    responsiveness to decrease as the number of systems subscribed to
    CloudForms System Engine increases. This erratum updates to Candlepin
    0.7.19, which corrects the performance issues. (BZ#896261)

    * CloudForms System Engine would not fetch Extended Update Service (EUS)
    entitlements. This blocked the user from seeing and enabling EUS
    repositories. This update revises the manifest upload and deletion code,
    which also corrects the behavior for fetching entitlements. System Engine
    now fetches EUS entitlements. (BZ#896265)

    * Issues with menu widths caused the localized UI to not render certain
    menu items. This update corrects the style for the System Engine UI. The
    Web UI now renders the menu items correctly. (BZ#903702)

    Refer to the CloudForms 1.1.2 Release Notes for further information about
    this release. The Release Notes will be available shortly from
    https://access.redhat.com/knowledge/docs/

    To upgrade, follow the upgrade instructions in the CloudForms Installation
    Guide, section 4.1. Upgrading CloudForms System Engine:

    https://access.redhat.com/knowledge/docs/en-US/CloudForms/1.1/html/Installation_Guide/index.html

    Users of CloudForms System Engine are advised to upgrade to these updated
    packages.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/knowledge/docs/");
  # https://access.redhat.com/knowledge/docs/en-US/CloudForms/1.1/html/Installation_Guide/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b59a1d3b");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=807455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=879094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=896251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=896253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=896261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=896265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=903702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=904128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=906207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=907250");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2013/rhsa-2013_0547.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81011277");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:0547");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-6116");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2012-5561");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-api-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-cli-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-glue-candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-glue-pulp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-selinux");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/cf-se/1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/cf-se/1/os',
      'content/dist/rhel/server/6/6Server/x86_64/cf-se/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'candlepin-0.7.19-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'candlepin-devel-0.7.19-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'candlepin-selinux-0.7.19-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'candlepin-tomcat6-0.7.19-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'katello-1.1.12.2-5.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'katello-all-1.1.12.2-5.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'katello-api-docs-1.1.12.2-5.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'katello-cli-1.1.8-14.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'katello-cli-common-1.1.8-14.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'katello-common-1.1.12.2-5.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'katello-configure-1.1.9-13.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'katello-glue-candlepin-1.1.12.2-5.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'katello-glue-pulp-1.1.12.2-5.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'},
      {'reference':'katello-selinux-1.1.1-5.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'candlepin / candlepin-devel / candlepin-selinux / candlepin-tomcat6 / etc');
}
