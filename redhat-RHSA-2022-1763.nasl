##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:1763. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161045);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/08");

  script_cve_id("CVE-2021-43818");
  script_xref(name:"RHSA", value:"2022:1763");

  script_name(english:"RHEL 8 : python39:3.9 and python39-devel:3.9 (RHSA-2022:1763)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for python39:3.9 / python39-devel:3.9.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2022:1763 advisory.

    Python is an interpreted, interactive, object-oriented programming language, which includes modules,
    classes, exceptions, very high level dynamic data types and dynamic typing. Python supports interfaces to
    many system calls and libraries, as well as to various windowing systems.

    Security Fix(es):

    * python-lxml: HTML Cleaner allows crafted and SVG embedded scripts to pass through (CVE-2021-43818)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional Changes:

    For detailed information on changes in this release, see the Red Hat Enterprise Linux 8.6 Release Notes
    linked from the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/8.6_release_notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9341665d");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_1763.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c95c95c2");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2003102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2006790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2032569");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL python39:3.9 / python39-devel:3.9 packages based on the guidance in RHSA-2022:1763.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43818");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PyYAML");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-toml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-toml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-wheel-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:scipy");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  'python39:3.9': [
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
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi8/8/aarch64/appstream/debug',
        'content/public/ubi/dist/ubi8/8/aarch64/appstream/os',
        'content/public/ubi/dist/ubi8/8/aarch64/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi8/8/ppc64le/appstream/debug',
        'content/public/ubi/dist/ubi8/8/ppc64le/appstream/os',
        'content/public/ubi/dist/ubi8/8/ppc64le/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi8/8/s390x/appstream/debug',
        'content/public/ubi/dist/ubi8/8/s390x/appstream/os',
        'content/public/ubi/dist/ubi8/8/s390x/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi8/8/x86_64/appstream/debug',
        'content/public/ubi/dist/ubi8/8/x86_64/appstream/os',
        'content/public/ubi/dist/ubi8/8/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'python39-3.9.7-1.module+el8.6.0+12577+62b8d0a1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-cffi-1.14.3-2.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-chardet-3.0.4-19.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-cryptography-3.3.1-2.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-devel-3.9.7-1.module+el8.6.0+12577+62b8d0a1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-idle-3.9.7-1.module+el8.6.0+12577+62b8d0a1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-idna-2.10-3.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-libs-3.9.7-1.module+el8.6.0+12577+62b8d0a1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-lxml-4.6.5-1.module+el8.6.0+13933+9cf0c87c', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-mod_wsgi-4.7.1-4.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-numpy-1.19.4-3.module+el8.5.0+12204+54860423', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-numpy-doc-1.19.4-3.module+el8.5.0+12204+54860423', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-numpy-f2py-1.19.4-3.module+el8.5.0+12204+54860423', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-pip-20.2.4-7.module+el8.6.0+13003+6bb2c488', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-pip-wheel-20.2.4-7.module+el8.6.0+13003+6bb2c488', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-ply-3.11-10.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-psutil-5.8.0-4.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-psycopg2-2.8.6-2.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-psycopg2-doc-2.8.6-2.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-psycopg2-tests-2.8.6-2.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-pycparser-2.20-3.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-PyMySQL-0.10.1-2.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-pysocks-1.7.1-4.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-pyyaml-5.4.1-1.module+el8.5.0+10613+59a13ec4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-requests-2.25.0-2.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-rpm-macros-3.9.7-1.module+el8.6.0+12577+62b8d0a1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-scipy-1.5.4-3.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-setuptools-50.3.2-4.module+el8.5.0+12204+54860423', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-setuptools-wheel-50.3.2-4.module+el8.5.0+12204+54860423', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-six-1.15.0-3.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-test-3.9.7-1.module+el8.6.0+12577+62b8d0a1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-tkinter-3.9.7-1.module+el8.6.0+12577+62b8d0a1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-toml-0.10.1-5.module+el8.4.0+9822+20bf1249', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-urllib3-1.25.10-4.module+el8.5.0+11712+ea2d2be1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python39-wheel-0.35.1-4.module+el8.5.0+12204+54860423', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'python39-wheel-wheel-0.35.1-4.module+el8.5.0+12204+54860423', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/python39');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python39:3.9');
if ('3.9' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python39:' + module_ver);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python39:3.9');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python39 / python39-PyMySQL / python39-cffi / python39-chardet / etc');
}
