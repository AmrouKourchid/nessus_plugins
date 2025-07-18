#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:7050. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185668);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2007-4559", "CVE-2023-32681");
  script_xref(name:"RHSA", value:"2023:7050");

  script_name(english:"RHEL 8 : python38:3.8 and python38-devel:3.8 (RHSA-2023:7050)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for python38:3.8 / python38-devel:3.8.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:7050 advisory.

    Python is an interpreted, interactive, object-oriented programming language, which includes modules,
    classes, exceptions, very high level dynamic data types and dynamic typing. Python supports interfaces to
    many system calls and libraries, as well as to various windowing systems.

    Security Fix(es):

    * python: tarfile module directory traversal (CVE-2007-4559)

    * python-requests: Unintended leak of Proxy-Authorization header (CVE-2023-32681)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional Changes:

    For detailed information on changes in this release, see the Red Hat Enterprise Linux 8.9 Release Notes
    linked from the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/8.9_release_notes/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?819248f8");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_7050.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9269647a");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2209469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2217853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2217862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2218267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2222717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=263261");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:7050");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL python38:3.8 / python38-devel:3.8 packages based on the guidance in RHSA-2023:7050.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-4559");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-32681");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-32681");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 402);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PyYAML");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-asn1crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-atomicwrites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-more-itertools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wcwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-asn1crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-atomicwrites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-more-itertools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-wcwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python38-wheel-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:scipy");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  'python38:3.8': [
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
        {'reference':'python38-3.8.17-2.module+el8.9.0+19642+a12b4af6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-asn1crypto-1.2.0-3.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-babel-2.7.0-11.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-cffi-1.13.2-3.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-chardet-3.0.4-19.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-cryptography-2.8-3.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-Cython-0.29.14-4.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-debug-3.8.17-2.module+el8.9.0+19642+a12b4af6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-devel-3.8.17-2.module+el8.9.0+19642+a12b4af6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-idle-3.8.17-2.module+el8.9.0+19642+a12b4af6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-idna-2.8-6.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-jinja2-2.11.3-1.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-libs-3.8.17-2.module+el8.9.0+19642+a12b4af6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-lxml-4.4.1-7.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-markupsafe-1.1.1-6.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-mod_wsgi-4.6.8-5.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-numpy-1.17.3-7.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-numpy-doc-1.17.3-7.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-numpy-f2py-1.17.3-7.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pip-19.3.1-7.module+el8.9.0+19642+a12b4af6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pip-wheel-19.3.1-7.module+el8.9.0+19642+a12b4af6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-ply-3.11-10.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-psutil-5.6.4-4.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-psycopg2-2.8.4-4.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-psycopg2-doc-2.8.4-4.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-psycopg2-tests-2.8.4-4.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pycparser-2.19-3.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-PyMySQL-0.10.1-1.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pysocks-1.7.1-4.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pytz-2019.3-4.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pyyaml-5.4.1-1.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-requests-2.22.0-10.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-rpm-macros-3.8.17-2.module+el8.9.0+19642+a12b4af6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-scipy-1.3.1-5.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-setuptools-41.6.0-5.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-setuptools-wheel-41.6.0-5.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-six-1.12.0-10.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-test-3.8.17-2.module+el8.9.0+19642+a12b4af6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-tkinter-3.8.17-2.module+el8.9.0+19642+a12b4af6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-urllib3-1.25.7-5.module+el8.9.0+19598+4a60c7b7', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-wheel-0.33.6-6.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-wheel-wheel-0.33.6-6.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ],
  'python38-devel:3.8': [
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8.10/aarch64/codeready-builder/debug',
        'content/dist/rhel8/8.10/aarch64/codeready-builder/os',
        'content/dist/rhel8/8.10/aarch64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.10/ppc64le/codeready-builder/debug',
        'content/dist/rhel8/8.10/ppc64le/codeready-builder/os',
        'content/dist/rhel8/8.10/ppc64le/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.10/s390x/codeready-builder/debug',
        'content/dist/rhel8/8.10/s390x/codeready-builder/os',
        'content/dist/rhel8/8.10/s390x/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.10/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8.10/x86_64/codeready-builder/os',
        'content/dist/rhel8/8.10/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.6/aarch64/codeready-builder/debug',
        'content/dist/rhel8/8.6/aarch64/codeready-builder/os',
        'content/dist/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.6/ppc64le/codeready-builder/debug',
        'content/dist/rhel8/8.6/ppc64le/codeready-builder/os',
        'content/dist/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.6/s390x/codeready-builder/debug',
        'content/dist/rhel8/8.6/s390x/codeready-builder/os',
        'content/dist/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.6/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8.6/x86_64/codeready-builder/os',
        'content/dist/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.8/aarch64/codeready-builder/debug',
        'content/dist/rhel8/8.8/aarch64/codeready-builder/os',
        'content/dist/rhel8/8.8/aarch64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.8/ppc64le/codeready-builder/debug',
        'content/dist/rhel8/8.8/ppc64le/codeready-builder/os',
        'content/dist/rhel8/8.8/ppc64le/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.8/s390x/codeready-builder/debug',
        'content/dist/rhel8/8.8/s390x/codeready-builder/os',
        'content/dist/rhel8/8.8/s390x/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.8/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8.8/x86_64/codeready-builder/os',
        'content/dist/rhel8/8.8/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.9/aarch64/codeready-builder/debug',
        'content/dist/rhel8/8.9/aarch64/codeready-builder/os',
        'content/dist/rhel8/8.9/aarch64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.9/ppc64le/codeready-builder/debug',
        'content/dist/rhel8/8.9/ppc64le/codeready-builder/os',
        'content/dist/rhel8/8.9/ppc64le/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.9/s390x/codeready-builder/debug',
        'content/dist/rhel8/8.9/s390x/codeready-builder/os',
        'content/dist/rhel8/8.9/s390x/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8.9/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8.9/x86_64/codeready-builder/os',
        'content/dist/rhel8/8.9/x86_64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/aarch64/codeready-builder/debug',
        'content/dist/rhel8/8/aarch64/codeready-builder/os',
        'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
        'content/dist/rhel8/8/ppc64le/codeready-builder/os',
        'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/s390x/codeready-builder/debug',
        'content/dist/rhel8/8/s390x/codeready-builder/os',
        'content/dist/rhel8/8/s390x/codeready-builder/source/SRPMS',
        'content/dist/rhel8/8/x86_64/codeready-builder/debug',
        'content/dist/rhel8/8/x86_64/codeready-builder/os',
        'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'python38-atomicwrites-1.3.0-8.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-attrs-19.3.0-3.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-more-itertools-7.2.0-5.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-packaging-19.2-3.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pluggy-0.13.0-3.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-py-1.8.0-8.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pyparsing-2.4.5-3.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-pytest-4.6.6-3.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python38-wcwidth-0.1.7-16.module+el8.9.0+19592+4b459c9b', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python38-devel:3.8 / python38:3.8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python38 / python38-Cython / python38-PyMySQL / python38-asn1crypto / etc');
}
