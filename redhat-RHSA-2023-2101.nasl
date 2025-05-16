#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:2101. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194312);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2022-40899", "CVE-2023-23969", "CVE-2023-24580");
  script_xref(name:"RHSA", value:"2023:2101");

  script_name(english:"RHEL 8 : RHUI 4.4.0  - Security Fixes, Bug Fixes, and Enhancements Update (Moderate) (RHSA-2023:2101)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:2101 advisory.

    Red Hat Update Infrastructure (RHUI) offers a highly scalable, highly redundant framework that enables you
    to manage repositories and content. It also enables cloud providers to deliver content and updates to Red
    Hat Enterprise Linux (RHEL) instances.

    Security Fix(es):
    * Django: Potential denial-of-service vulnerability due to large Accept-Language header values
    (CVE-2023-23969)

    * Django: Potential denial-of-service vulnerability when uploading multiple files (CVE-2023-24580)

    * Future: Remote attackers can cause denial-of-service using crafted Set-Cookie header from a malicious
    web server (CVE-2022-40899)

    This RHUI update fixes the following bugs:

    * Previously, when the `rhui-services-restart` command was run, it restarted only those `pulpcore-worker`
    services that were already running and ignored services that were not running. With this update, the
    `rhui-services-restart` command restarts all `pulpcore-worker` services irrespective of their status.

    * Previously, the `rhui-manager status` command returned an incorrect exit status when there was a
    problem. With this update, the issue has been fixed and the command now returns the correct exit status.
    (BZ#2174633)

    * Previously, `rhui-installer` ignored the `--rhua-mount-options` parameter and only used the read-write
    (`rw`) mount option to set up RHUI remote share. With this update, `rhui-installer` uses the `--rhua-
    mount-options` parameter. However, `rhui-installer` still uses the read-write (`rw`) option by default.
    (BZ#2174316)

    * Previously, when you ran `rhui-installer`, it rewrote the `/etc/rhui/rhui-tools.conf` file, resetting
    all container-related settings. With this update, the command saves the container-related settings from
    the `/etc/rhui/rhui-tools.conf` file and restores them after the file is rewritten.

    This RHUI update introduces the following enhancements:

    * The `rhui-installer` command now supports the `--pulp-workers _COUNT_` argument. RHUI administrators can
    use this argument to set up a number of Pulp workers. (BZ#2036408)

    * You can now configure CDS nodes to never fetch non-exported content from the RHUA node. To configure the
    node, rerun the `rhui-installer` command with the `--fetch-missing-symlinks False` argument, and then
    apply this configuration to all CDS nodes. If you configure your CDS nodes this way, ensure that the
    content has been exported before RHUI clients start consuming it. (BZ#2084950)

    * Support for containers in RHUI is disabled by default. If you want to use containers, you must manually
    enable container support by rerunning `rhui-installer` with the `--container-support-enabled True`
    argument, and then applying this configuration to all CDS nodes.

    * Transport Layer Security (TLS) 1.3 and HTTP Strict Transport Security (HSTS)  is now enabled in RHUI.
    This update improves overall RHUI security and also removes unsafe ciphers from the `nginx` configuration
    on CDS nodes. (BZ#1887903)

    * You can now remove packages from custom repositories using the text user interface (TUI) as well as the
    command line. For more information, see the release notes or the product documentation.(BZ#2165444)

    * You can now set up the Alternate Content Source (ACS) configuration in RHUI to quickly synchronize new
    repositories and content by substituting remote content with matching content that is available locally or
    geographically closer to your instance of RHUI. For more information, see the release notes or the product
    documentation. (BZ#2001087)

    * You can now use a custom prefix, or no prefix at all, when naming your RHUI repositories. You can change
    the prefix by rerunning the `rhui-installer` command with the `--client-repo-prefix <prefix>` argument. To
    remove the prefix entirely, use two quotation marks () as the `<prefix>` parameter. For more
    information, see the release notes or the product documentation.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2036408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2084950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2165444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2165866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2166457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2169402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2174316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2174633");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-134");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-148");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-199");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-230");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-342");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-354");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-362");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-368");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-370");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-371");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-372");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-376");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/RHUI-377");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_2101.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c5b1034");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:2101");
  script_set_attribute(attribute:"solution", value:
"Update the affected python39-django and / or python39-future packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24580");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(400);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-future");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-future");
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
      'content/dist/layered/rhel8/x86_64/rhui/4/debug',
      'content/dist/layered/rhel8/x86_64/rhui/4/os',
      'content/dist/layered/rhel8/x86_64/rhui/4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python39-django-3.2.18-1.0.1.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-23969', 'CVE-2023-24580']},
      {'reference':'python39-future-0.18.3-1.0.1.el8ui', 'release':'8', 'el_string':'el8ui', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40899']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python39-django / python39-future');
}
