#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:3261. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233507);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/29");

  script_cve_id("CVE-2024-7347");
  script_xref(name:"RHSA", value:"2025:3261");

  script_name(english:"RHEL 9 : nginx:1.22 (RHSA-2025:3261)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for nginx:1.22.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2025:3261 advisory.

    nginx is a web and proxy server supporting HTTP and other protocols, with a focus on high concurrency,
    performance, and low memory usage.

    Security Fix(es):

    * nginx: specially crafted MP4 file may cause denial of service (CVE-2024-7347)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_3261.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c271af4f");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:3261");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL nginx:1.22 package based on the guidance in RHSA-2025:3261.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7347");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(126);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nginx-all-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nginx-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nginx-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nginx-mod-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nginx-mod-http-image-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nginx-mod-http-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nginx-mod-http-xslt-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nginx-mod-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nginx-mod-stream");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'nginx:1.22': [
    {
      'repo_relative_urls': [
        'content/dist/rhel9/9.1/aarch64/appstream/debug',
        'content/dist/rhel9/9.1/aarch64/appstream/os',
        'content/dist/rhel9/9.1/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.1/ppc64le/appstream/debug',
        'content/dist/rhel9/9.1/ppc64le/appstream/os',
        'content/dist/rhel9/9.1/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.1/s390x/appstream/debug',
        'content/dist/rhel9/9.1/s390x/appstream/os',
        'content/dist/rhel9/9.1/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.1/x86_64/appstream/debug',
        'content/dist/rhel9/9.1/x86_64/appstream/os',
        'content/dist/rhel9/9.1/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.2/aarch64/appstream/debug',
        'content/dist/rhel9/9.2/aarch64/appstream/os',
        'content/dist/rhel9/9.2/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.2/ppc64le/appstream/debug',
        'content/dist/rhel9/9.2/ppc64le/appstream/os',
        'content/dist/rhel9/9.2/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.2/s390x/appstream/debug',
        'content/dist/rhel9/9.2/s390x/appstream/os',
        'content/dist/rhel9/9.2/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.2/x86_64/appstream/debug',
        'content/dist/rhel9/9.2/x86_64/appstream/os',
        'content/dist/rhel9/9.2/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.3/aarch64/appstream/debug',
        'content/dist/rhel9/9.3/aarch64/appstream/os',
        'content/dist/rhel9/9.3/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.3/ppc64le/appstream/debug',
        'content/dist/rhel9/9.3/ppc64le/appstream/os',
        'content/dist/rhel9/9.3/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.3/s390x/appstream/debug',
        'content/dist/rhel9/9.3/s390x/appstream/os',
        'content/dist/rhel9/9.3/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.3/x86_64/appstream/debug',
        'content/dist/rhel9/9.3/x86_64/appstream/os',
        'content/dist/rhel9/9.3/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.4/aarch64/appstream/debug',
        'content/dist/rhel9/9.4/aarch64/appstream/os',
        'content/dist/rhel9/9.4/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.4/ppc64le/appstream/debug',
        'content/dist/rhel9/9.4/ppc64le/appstream/os',
        'content/dist/rhel9/9.4/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.4/s390x/appstream/debug',
        'content/dist/rhel9/9.4/s390x/appstream/os',
        'content/dist/rhel9/9.4/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.4/x86_64/appstream/debug',
        'content/dist/rhel9/9.4/x86_64/appstream/os',
        'content/dist/rhel9/9.4/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.5/aarch64/appstream/debug',
        'content/dist/rhel9/9.5/aarch64/appstream/os',
        'content/dist/rhel9/9.5/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.5/ppc64le/appstream/debug',
        'content/dist/rhel9/9.5/ppc64le/appstream/os',
        'content/dist/rhel9/9.5/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.5/s390x/appstream/debug',
        'content/dist/rhel9/9.5/s390x/appstream/os',
        'content/dist/rhel9/9.5/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.5/x86_64/appstream/debug',
        'content/dist/rhel9/9.5/x86_64/appstream/os',
        'content/dist/rhel9/9.5/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.6/aarch64/appstream/debug',
        'content/dist/rhel9/9.6/aarch64/appstream/os',
        'content/dist/rhel9/9.6/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.6/ppc64le/appstream/debug',
        'content/dist/rhel9/9.6/ppc64le/appstream/os',
        'content/dist/rhel9/9.6/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.6/s390x/appstream/debug',
        'content/dist/rhel9/9.6/s390x/appstream/os',
        'content/dist/rhel9/9.6/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.6/x86_64/appstream/debug',
        'content/dist/rhel9/9.6/x86_64/appstream/os',
        'content/dist/rhel9/9.6/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.7/aarch64/appstream/debug',
        'content/dist/rhel9/9.7/aarch64/appstream/os',
        'content/dist/rhel9/9.7/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.7/ppc64le/appstream/debug',
        'content/dist/rhel9/9.7/ppc64le/appstream/os',
        'content/dist/rhel9/9.7/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.7/s390x/appstream/debug',
        'content/dist/rhel9/9.7/s390x/appstream/os',
        'content/dist/rhel9/9.7/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.7/x86_64/appstream/debug',
        'content/dist/rhel9/9.7/x86_64/appstream/os',
        'content/dist/rhel9/9.7/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9/aarch64/appstream/debug',
        'content/dist/rhel9/9/aarch64/appstream/os',
        'content/dist/rhel9/9/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9/ppc64le/appstream/debug',
        'content/dist/rhel9/9/ppc64le/appstream/os',
        'content/dist/rhel9/9/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9/s390x/appstream/debug',
        'content/dist/rhel9/9/s390x/appstream/os',
        'content/dist/rhel9/9/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9/x86_64/appstream/debug',
        'content/dist/rhel9/9/x86_64/appstream/os',
        'content/dist/rhel9/9/x86_64/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi9/9/aarch64/appstream/debug',
        'content/public/ubi/dist/ubi9/9/aarch64/appstream/os',
        'content/public/ubi/dist/ubi9/9/aarch64/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi9/9/ppc64le/appstream/debug',
        'content/public/ubi/dist/ubi9/9/ppc64le/appstream/os',
        'content/public/ubi/dist/ubi9/9/ppc64le/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi9/9/s390x/appstream/debug',
        'content/public/ubi/dist/ubi9/9/s390x/appstream/os',
        'content/public/ubi/dist/ubi9/9/s390x/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi9/9/x86_64/appstream/debug',
        'content/public/ubi/dist/ubi9/9/x86_64/appstream/os',
        'content/public/ubi/dist/ubi9/9/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'nginx-1.22.1-8.module+el9.5.0+22953+b175c265.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nginx-all-modules-1.22.1-8.module+el9.5.0+22953+b175c265.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nginx-core-1.22.1-8.module+el9.5.0+22953+b175c265.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nginx-filesystem-1.22.1-8.module+el9.5.0+22953+b175c265.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nginx-mod-devel-1.22.1-8.module+el9.5.0+22953+b175c265.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nginx-mod-http-image-filter-1.22.1-8.module+el9.5.0+22953+b175c265.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nginx-mod-http-perl-1.22.1-8.module+el9.5.0+22953+b175c265.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nginx-mod-http-xslt-filter-1.22.1-8.module+el9.5.0+22953+b175c265.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nginx-mod-mail-1.22.1-8.module+el9.5.0+22953+b175c265.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'nginx-mod-stream-1.22.1-8.module+el9.5.0+22953+b175c265.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/nginx');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nginx:1.22');
if ('1.22' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module nginx:' + module_ver);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module nginx:1.22');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nginx / nginx-all-modules / nginx-core / nginx-filesystem / etc');
}
