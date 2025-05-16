#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:4070. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200882);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2023-4727");
  script_xref(name:"RHSA", value:"2024:4070");

  script_name(english:"RHEL 8 : Red Hat Certificate System 10.4 for RHEL 8 (RHSA-2024:4070)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for Red Hat Certificate System 10.4 for RHEL 8.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2024:4070 advisory.

    Red Hat Certificate System (RHCS) is a complete implementation of an enterprise software system designed
    to manage enterprise Public Key Infrastructure (PKI) deployments.

    Security fixes:

    - Token authentication bypass vulnerability (BZ2232221 - CVE-2023-4727)
    - Renaming the option ops-flag and ops-flag-mask (BZ2275455)
    - Rebase to TomcatJSS 7.7.4
    - Rename enableOCSP to enableRevocationCheck (BZ2275095)
    - Rebase to JSS 4.9.9
    - Enable revocation verification using CRL-DP (BZ2274531)

    Users of RHCS 10 are advised to upgrade to these updated packages.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_4070.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f39120f");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:4070");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat Certificate System 10.4 for RHEL 8 package based on the guidance in RHSA-2024:4070.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4727");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(305);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:idm-console-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jss-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ldapjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ldapjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-redhat-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-acme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-console-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-est");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-ocsp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-server-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-tks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-tps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcatjss");
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

var appstreams = {
  'redhat-pki:10': [
    {
      'repo_relative_urls': [
        'content/eus/rhel8/8.6/x86_64/certsys/10/debug',
        'content/eus/rhel8/8.6/x86_64/certsys/10/os',
        'content/eus/rhel8/8.6/x86_64/certsys/10/source/SRPMS',
        'content/eus/rhel8/8.8/x86_64/certsys/10/debug',
        'content/eus/rhel8/8.8/x86_64/certsys/10/os',
        'content/eus/rhel8/8.8/x86_64/certsys/10/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'idm-console-framework-1.3.0-1.module+el8pki+14677+1ef79a68', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jss-4.9.10-1.module+el8pki+21949+4b2d0700', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jss-javadoc-4.9.10-1.module+el8pki+21949+4b2d0700', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ldapjdk-4.23.0-1.module+el8pki+14677+1ef79a68', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ldapjdk-javadoc-4.23.0-1.module+el8pki+14677+1ef79a68', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-redhat-pki-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-10.13.11-1.module+el8pki+21949+4b2d0700', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-acme-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-base-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-base-java-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-ca-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-console-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-console-theme-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-est-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-javadoc-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-kra-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-ocsp-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-server-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-server-theme-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-symkey-10.13.11-1.module+el8pki+21949+4b2d0700', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-tks-10.13.11-1.module+el8pki+21949+4b2d0700', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-tools-10.13.11-1.module+el8pki+21949+4b2d0700', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-tps-10.13.11-1.module+el8pki+21949+4b2d0700', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'tomcatjss-7.7.4-1.module+el8pki+21738+33a5e23b', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/redhat-pki');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module redhat-pki:10');
if ('10' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module redhat-pki:' + module_ver);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module redhat-pki:10');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idm-console-framework / jss / jss-javadoc / ldapjdk / etc');
}
