#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:2985.
##

include('compat.inc');

if (description)
{
  script_id(200625);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id(
    "CVE-2022-40897",
    "CVE-2023-23931",
    "CVE-2023-27043",
    "CVE-2023-43804"
  );
  script_xref(name:"RLSA", value:"2024:2985");

  script_name(english:"Rocky Linux 8 : python39:3.9 and python39-devel:3.9 (RLSA-2024:2985)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:2985 advisory.

    * pypa-setuptools: Regular Expression Denial of Service (ReDoS) in package_index.py (CVE-2022-40897)

    * python-cryptography: memory corruption via immutable objects (CVE-2023-23931)

    * python: Parsing errors in email/_parseaddr.py lead to incorrect value in email address part of tuple
    (CVE-2023-27043)

    * python-urllib3: Cookie request header isn't stripped during cross-origin redirects (CVE-2023-43804)

Tenable has extracted the preceding description block directly from the Rocky Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:2985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2158559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2171817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2196183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242493");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-43804");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:Cython-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:PyYAML-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:numpy-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-cffi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-cryptography-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-lxml-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-psutil-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-psycopg2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-Cython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-cffi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-cryptography-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-iniconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-lxml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-more-itertools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-numpy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-ply");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-psutil-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-psycopg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pybind11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pybind11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-pyyaml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-scipy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-toml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-wcwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python39-wheel-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:scipy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var appstreams = {
    'python39-devel:3.9': [
      {'reference':'Cython-debugsource-0.29.21-5.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Cython-debugsource-0.29.21-5.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'numpy-debugsource-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'numpy-debugsource-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-cffi-debugsource-1.14.3-2.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-cffi-debugsource-1.14.3-2.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-cryptography-debugsource-3.3.1-3.module+el8.10.0+1697+7e517775', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-cryptography-debugsource-3.3.1-3.module+el8.10.0+1697+7e517775', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-lxml-debugsource-4.6.5-1.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-lxml-debugsource-4.6.5-1.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psutil-debugsource-5.8.0-4.module+el8.9.0+1357+a3b80af7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psutil-debugsource-5.8.0-4.module+el8.9.0+1357+a3b80af7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-debugsource-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-debugsource-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-attrs-20.3.0-2.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-debuginfo-1.14.3-2.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-debuginfo-1.14.3-2.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-chardet-3.0.4-19.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-3.module+el8.10.0+1697+7e517775', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-3.module+el8.10.0+1697+7e517775', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-debuginfo-3.3.1-3.module+el8.10.0+1697+7e517775', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-debuginfo-3.3.1-3.module+el8.10.0+1697+7e517775', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-Cython-0.29.21-5.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-Cython-0.29.21-5.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-Cython-debuginfo-0.29.21-5.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-Cython-debuginfo-0.29.21-5.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-iniconfig-1.1.1-2.module+el8.9.0+1332+dd574197', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.5-1.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.5-1.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-debuginfo-4.6.5-1.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-debuginfo-4.6.5-1.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-7.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-7.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-more-itertools-8.5.0-2.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-debuginfo-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-debuginfo-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-doc-1.19.4-3.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-packaging-20.4-4.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-20.2.4-9.module+el8.10.0+1721+e52d6351', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-wheel-20.2.4-9.module+el8.10.0+1721+e52d6351', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pluggy-0.13.1-3.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-ply-3.11-10.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module+el8.9.0+1357+a3b80af7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module+el8.9.0+1357+a3b80af7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-debuginfo-5.8.0-4.module+el8.9.0+1357+a3b80af7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-debuginfo-5.8.0-4.module+el8.9.0+1357+a3b80af7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-debuginfo-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-debuginfo-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-py-1.10.0-1.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-2.7.1-1.module+el8.9.0+1357+a3b80af7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-2.7.1-1.module+el8.9.0+1357+a3b80af7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-devel-2.7.1-1.module+el8.9.0+1357+a3b80af7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-devel-2.7.1-1.module+el8.9.0+1357+a3b80af7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pycparser-2.20-3.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-PyMySQL-0.10.1-2.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyparsing-2.4.7-5.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pysocks-1.7.1-4.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pytest-6.0.2-2.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-debuginfo-5.4.1-1.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-debuginfo-5.4.1-1.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-requests-2.25.0-3.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-5.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-5.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-debuginfo-1.5.4-5.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-debuginfo-1.5.4-5.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-50.3.2-5.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-wheel-50.3.2-5.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-six-1.15.0-3.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-toml-0.10.1-5.module+el8.9.0+1332+dd574197', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-urllib3-1.25.10-5.module+el8.10.0+1545+03246da9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-wcwidth-0.2.5-3.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-wheel-0.35.1-4.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python39-wheel-wheel-0.35.1-4.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'PyYAML-debugsource-5.4.1-1.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'PyYAML-debugsource-5.4.1-1.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'scipy-debugsource-1.5.4-5.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'scipy-debugsource-1.5.4-5.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ],
    'python39:3.9': [
      {'reference':'Cython-debugsource-0.29.21-5.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Cython-debugsource-0.29.21-5.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'numpy-debugsource-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'numpy-debugsource-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-cffi-debugsource-1.14.3-2.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-cffi-debugsource-1.14.3-2.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-cryptography-debugsource-3.3.1-3.module+el8.10.0+1697+7e517775', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-cryptography-debugsource-3.3.1-3.module+el8.10.0+1697+7e517775', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-lxml-debugsource-4.6.5-1.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-lxml-debugsource-4.6.5-1.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psutil-debugsource-5.8.0-4.module+el8.9.0+1357+a3b80af7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psutil-debugsource-5.8.0-4.module+el8.9.0+1357+a3b80af7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-debugsource-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-debugsource-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-attrs-20.3.0-2.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-1.14.3-2.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-debuginfo-1.14.3-2.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cffi-debuginfo-1.14.3-2.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-chardet-3.0.4-19.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-3.module+el8.10.0+1697+7e517775', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-3.3.1-3.module+el8.10.0+1697+7e517775', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-debuginfo-3.3.1-3.module+el8.10.0+1697+7e517775', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-cryptography-debuginfo-3.3.1-3.module+el8.10.0+1697+7e517775', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-Cython-0.29.21-5.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-Cython-0.29.21-5.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-Cython-debuginfo-0.29.21-5.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-Cython-debuginfo-0.29.21-5.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-iniconfig-1.1.1-2.module+el8.9.0+1332+dd574197', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.5-1.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-4.6.5-1.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-debuginfo-4.6.5-1.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-lxml-debuginfo-4.6.5-1.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-7.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-mod_wsgi-4.7.1-7.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-more-itertools-8.5.0-2.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-debuginfo-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-debuginfo-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-doc-1.19.4-3.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-numpy-f2py-1.19.4-3.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-packaging-20.4-4.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-20.2.4-9.module+el8.10.0+1721+e52d6351', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pip-wheel-20.2.4-9.module+el8.10.0+1721+e52d6351', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pluggy-0.13.1-3.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-ply-3.11-10.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module+el8.9.0+1357+a3b80af7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-5.8.0-4.module+el8.9.0+1357+a3b80af7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-debuginfo-5.8.0-4.module+el8.9.0+1357+a3b80af7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psutil-debuginfo-5.8.0-4.module+el8.9.0+1357+a3b80af7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-debuginfo-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-debuginfo-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-doc-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-psycopg2-tests-2.8.6-3.module+el8.10.0+1660+b5b6f004', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-py-1.10.0-1.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-2.7.1-1.module+el8.9.0+1357+a3b80af7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-2.7.1-1.module+el8.9.0+1357+a3b80af7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-devel-2.7.1-1.module+el8.9.0+1357+a3b80af7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pybind11-devel-2.7.1-1.module+el8.9.0+1357+a3b80af7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pycparser-2.20-3.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-PyMySQL-0.10.1-2.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyparsing-2.4.7-5.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pysocks-1.7.1-4.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pytest-6.0.2-2.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-5.4.1-1.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-debuginfo-5.4.1-1.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-pyyaml-debuginfo-5.4.1-1.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-requests-2.25.0-3.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-5.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-1.5.4-5.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-debuginfo-1.5.4-5.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-scipy-debuginfo-1.5.4-5.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-50.3.2-5.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-setuptools-wheel-50.3.2-5.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-six-1.15.0-3.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-toml-0.10.1-5.module+el8.9.0+1332+dd574197', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-urllib3-1.25.10-5.module+el8.10.0+1545+03246da9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-wcwidth-0.2.5-3.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python39-wheel-0.35.1-4.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python39-wheel-wheel-0.35.1-4.module+el8.10.0+1582+bc278001', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'PyYAML-debugsource-5.4.1-1.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'PyYAML-debugsource-5.4.1-1.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'scipy-debugsource-1.5.4-5.module+el8.10.0+1582+bc278001', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'scipy-debugsource-1.5.4-5.module+el8.10.0+1582+bc278001', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RockyLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python39-devel:3.9 / python39:3.9');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Cython-debugsource / PyYAML-debugsource / numpy-debugsource / etc');
}
