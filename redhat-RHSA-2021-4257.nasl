#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:4257. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155086);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2021-26690", "CVE-2021-30641");
  script_xref(name:"IAVA", value:"2021-A-0259-S");
  script_xref(name:"RHSA", value:"2021:4257");

  script_name(english:"RHEL 8 : httpd:2.4 (RHSA-2021:4257)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:4257 advisory.

    The httpd packages provide the Apache HTTP Server, a powerful, efficient, and extensible web server.

    Security Fix(es):

    * httpd: mod_session: NULL pointer dereference when parsing Cookie header (CVE-2021-26690)

    * httpd: Unexpected URL matching with 'MergeSlashes OFF' (CVE-2021-30641)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional Changes:

    For detailed information on changes in this release, see the Red Hat Enterprise Linux 8.5 Release Notes
    linked from the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/8.5_release_notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7240878e");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_4257.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c75dae1a");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:4257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1905613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1934741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1935742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1937334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1952557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1966729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1966743");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30641");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 476);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var appstreams = {
  'httpd:2.4': [
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8.10/aarch64/appstream/debug',
        'content/dist/rhel8/8.10/aarch64/appstream/os',
        'content/dist/rhel8/8.10/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/ppc64le/appstream/debug',
        'content/dist/rhel8/8.10/ppc64le/appstream/os',
        'content/dist/rhel8/8.10/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/s390x/appstream/debug',
        'content/dist/rhel8/8.10/s390x/appstream/os',
        'content/dist/rhel8/8.10/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/x86_64/appstream/debug',
        'content/dist/rhel8/8.10/x86_64/appstream/os',
        'content/dist/rhel8/8.10/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/aarch64/appstream/debug',
        'content/dist/rhel8/8.6/aarch64/appstream/os',
        'content/dist/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/ppc64le/appstream/debug',
        'content/dist/rhel8/8.6/ppc64le/appstream/os',
        'content/dist/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/s390x/appstream/debug',
        'content/dist/rhel8/8.6/s390x/appstream/os',
        'content/dist/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/x86_64/appstream/debug',
        'content/dist/rhel8/8.6/x86_64/appstream/os',
        'content/dist/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/aarch64/appstream/debug',
        'content/dist/rhel8/8.8/aarch64/appstream/os',
        'content/dist/rhel8/8.8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/ppc64le/appstream/debug',
        'content/dist/rhel8/8.8/ppc64le/appstream/os',
        'content/dist/rhel8/8.8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/s390x/appstream/debug',
        'content/dist/rhel8/8.8/s390x/appstream/os',
        'content/dist/rhel8/8.8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/x86_64/appstream/debug',
        'content/dist/rhel8/8.8/x86_64/appstream/os',
        'content/dist/rhel8/8.8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/aarch64/appstream/debug',
        'content/dist/rhel8/8.9/aarch64/appstream/os',
        'content/dist/rhel8/8.9/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/ppc64le/appstream/debug',
        'content/dist/rhel8/8.9/ppc64le/appstream/os',
        'content/dist/rhel8/8.9/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/s390x/appstream/debug',
        'content/dist/rhel8/8.9/s390x/appstream/os',
        'content/dist/rhel8/8.9/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/x86_64/appstream/debug',
        'content/dist/rhel8/8.9/x86_64/appstream/os',
        'content/dist/rhel8/8.9/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/aarch64/appstream/debug',
        'content/dist/rhel8/8/aarch64/appstream/os',
        'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/appstream/debug',
        'content/dist/rhel8/8/ppc64le/appstream/os',
        'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8/s390x/appstream/debug',
        'content/dist/rhel8/8/s390x/appstream/os',
        'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'httpd-2.4.37-41.module+el8.5.0+11772+c8e0c271', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpd-devel-2.4.37-41.module+el8.5.0+11772+c8e0c271', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpd-filesystem-2.4.37-41.module+el8.5.0+11772+c8e0c271', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpd-manual-2.4.37-41.module+el8.5.0+11772+c8e0c271', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpd-tools-2.4.37-41.module+el8.5.0+11772+c8e0c271', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mod_http2-1.15.7-3.module+el8.4.0+8625+d397f3da', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mod_ldap-2.4.37-41.module+el8.5.0+11772+c8e0c271', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mod_md-2.0.8-8.module+el8.3.0+6814+67d1e611', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'mod_proxy_html-2.4.37-41.module+el8.5.0+11772+c8e0c271', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'mod_session-2.4.37-41.module+el8.5.0+11772+c8e0c271', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mod_ssl-2.4.37-41.module+el8.5.0+11772+c8e0c271', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/httpd');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module httpd:2.4');
if ('2.4' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module httpd:' + module_ver);

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      foreach var package_array ( module_array['pkgs'] ) {
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
        if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module httpd:2.4');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd / httpd-devel / httpd-filesystem / httpd-manual / httpd-tools / etc');
}
