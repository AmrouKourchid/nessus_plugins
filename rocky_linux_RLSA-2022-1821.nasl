#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:1821.
##

include('compat.inc');

if (description)
{
  script_id(184762);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/14");

  script_cve_id(
    "CVE-2021-3733",
    "CVE-2021-3737",
    "CVE-2021-4189",
    "CVE-2021-43818",
    "CVE-2022-0391"
  );
  script_xref(name:"RLSA", value:"2022:1821");
  script_xref(name:"IAVA", value:"2021-A-0497-S");

  script_name(english:"Rocky Linux 8 : python27:2.7 (RLSA-2022:1821)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2022:1821 advisory.

  - There's a flaw in urllib's AbstractBasicAuthHandler class. An attacker who controls a malicious HTTP
    server that an HTTP client (such as web browser) connects to, could trigger a Regular Expression Denial of
    Service (ReDOS) during an authentication request with a specially crafted payload that is sent by the
    server to the client. The greatest threat that this flaw poses is to application availability.
    (CVE-2021-3733)

  - A flaw was found in python. An improperly handled HTTP response in the HTTP client code of python may
    allow a remote attacker, who controls the HTTP server, to make the client script enter an infinite loop,
    consuming CPU time. The highest threat from this vulnerability is to system availability. (CVE-2021-3737)

  - A flaw was found in Python, specifically in the FTP (File Transfer Protocol) client library in PASV
    (passive) mode. The issue is how the FTP client trusts the host from the PASV response by default. This
    flaw allows an attacker to set up a malicious FTP server that can trick FTP clients into connecting back
    to a given IP address and port. This vulnerability could lead to FTP client scanning ports, which
    otherwise would not have been possible. (CVE-2021-4189)

  - lxml is a library for processing XML and HTML in the Python language. Prior to version 4.6.5, the HTML
    Cleaner in lxml.html lets certain crafted script content pass through, as well as script content in SVG
    files embedded using data URIs. Users that employ the HTML cleaner in a security relevant context should
    upgrade to lxml 4.6.5 to receive a patch. There are no known workarounds available. (CVE-2021-43818)

  - A flaw was found in Python, specifically within the urllib.parse module. This module helps break Uniform
    Resource Locator (URL) strings into components. The issue involves how the urlparse method does not
    sanitize input and allows characters like '\r' and '\n' in the URL path. This flaw allows an attacker to
    input a crafted URL, leading to injection attacks. This flaw affects Python versions prior to 3.10.0b1,
    3.9.5, 3.8.11, 3.7.11 and 3.6.14. (CVE-2022-0391)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:1821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1995162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1995234");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2006792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2032569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2036020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2047376");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43818");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0391");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:Cython-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:PyYAML-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:numpy-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-coverage-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-lxml-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-nose-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-psycopg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-psycopg2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-psycopg2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-pymongo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-pymongo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-sqlalchemy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-Cython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-Cython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-backports");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-backports-ssl_match_hostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-bson-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-coverage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-coverage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-docs-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-docutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-funcsigs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-ipaddress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-lxml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-nose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-numpy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-numpy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-numpy-f2py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pip-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pluggy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-psycopg2-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-psycopg2-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-psycopg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-psycopg2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pymongo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pysocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pytest-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-pyyaml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-scipy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-setuptools-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-setuptools_scm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-sqlalchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-virtualenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python2-wheel-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:scipy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var module_ver = get_kb_item('Host/RockyLinux/appstream/python27');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python27:2.7');
if ('2.7' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python27:' + module_ver);

var appstreams = {
    'python27:2.7': [
      {'reference':'babel-2.5.1-10.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Cython-debugsource-0.28.1-7.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Cython-debugsource-0.28.1-7.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Cython-debugsource-0.28.1-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'Cython-debugsource-0.28.1-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'numpy-debugsource-1.14.2-16.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'numpy-debugsource-1.14.2-16.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'numpy-debugsource-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'numpy-debugsource-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python-coverage-debugsource-4.5.1-4.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-coverage-debugsource-4.5.1-4.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-coverage-debugsource-4.5.1-4.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-coverage-debugsource-4.5.1-4.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-lxml-debugsource-4.2.3-6.module+el8.6.0+793+57002515', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-lxml-debugsource-4.2.3-6.module+el8.6.0+793+57002515', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-nose-docs-1.3.7-31.module+el8.5.0+671+195e4563', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-debuginfo-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-debuginfo-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-debuginfo-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-debuginfo-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-debugsource-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-debugsource-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-debugsource-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-debugsource-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-doc-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-doc-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-doc-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-psycopg2-doc-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debuginfo-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debuginfo-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debuginfo-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debuginfo-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debugsource-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debugsource-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debugsource-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debugsource-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-sqlalchemy-doc-1.3.2-2.module+el8.3.0+120+426d8baf', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-sqlalchemy-doc-1.3.2-2.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-attrs-17.4.0-10.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-attrs-17.4.0-10.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-babel-2.5.1-10.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-backports-1.0-16.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-backports-1.0-16.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-backports-ssl_match_hostname-3.5.0.1-12.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-bson-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-bson-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-bson-debuginfo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-bson-debuginfo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-chardet-3.0.4-10.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-chardet-3.0.4-10.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-coverage-4.5.1-4.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-coverage-4.5.1-4.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-coverage-4.5.1-4.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-coverage-4.5.1-4.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-coverage-debuginfo-4.5.1-4.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-coverage-debuginfo-4.5.1-4.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-coverage-debuginfo-4.5.1-4.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-coverage-debuginfo-4.5.1-4.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-Cython-0.28.1-7.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-Cython-0.28.1-7.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-Cython-0.28.1-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-Cython-0.28.1-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-Cython-debuginfo-0.28.1-7.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-Cython-debuginfo-0.28.1-7.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-Cython-debuginfo-0.28.1-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-Cython-debuginfo-0.28.1-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-debug-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-debug-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-debuginfo-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-debuginfo-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-debugsource-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-debugsource-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-devel-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-devel-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-dns-1.15.0-10.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-dns-1.15.0-10.module+el8.7.0+1062+663ba31c', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-docs-2.7.16-2.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-docs-info-2.7.16-2.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-docutils-0.14-12.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-funcsigs-1.0.2-13.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-idna-2.5-7.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-idna-2.5-7.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-ipaddress-1.0.18-6.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-jinja2-2.10-9.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-jinja2-2.10-9.module+el8.7.0+1062+663ba31c', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-libs-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-libs-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-lxml-4.2.3-6.module+el8.6.0+793+57002515', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-lxml-4.2.3-6.module+el8.6.0+793+57002515', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-lxml-debuginfo-4.2.3-6.module+el8.6.0+793+57002515', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-lxml-debuginfo-4.2.3-6.module+el8.6.0+793+57002515', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-markupsafe-0.23-19.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-markupsafe-0.23-19.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-markupsafe-0.23-19.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-mock-2.0.0-13.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-nose-1.3.7-31.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-numpy-1.14.2-16.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-1.14.2-16.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-debuginfo-1.14.2-16.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-debuginfo-1.14.2-16.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-debuginfo-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-debuginfo-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-doc-1.14.2-16.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-doc-1.14.2-16.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-f2py-1.14.2-16.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-f2py-1.14.2-16.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-f2py-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-numpy-f2py-1.14.2-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-pip-9.0.3-19.module+el8.6.0+793+57002515', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pip-wheel-9.0.3-19.module+el8.6.0+793+57002515', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pluggy-0.6.0-8.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pluggy-0.6.0-8.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debug-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debug-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debug-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debug-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debug-debuginfo-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debug-debuginfo-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debug-debuginfo-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debug-debuginfo-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debuginfo-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debuginfo-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debuginfo-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-debuginfo-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-tests-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-tests-2.7.5-7.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-tests-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-psycopg2-tests-2.7.5-7.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-py-1.5.3-6.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-py-1.5.3-6.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pygments-2.2.0-22.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-debuginfo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-debuginfo-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-gridfs-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pymongo-gridfs-3.7.0-1.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-PyMySQL-0.8.0-10.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-PyMySQL-0.8.0-10.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pysocks-1.6.8-6.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pysocks-1.6.8-6.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytest-3.4.2-13.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytest-3.4.2-13.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytest-mock-1.9.0-4.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytz-2017.2-12.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pytz-2017.2-12.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pyyaml-3.12-16.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pyyaml-3.12-16.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pyyaml-3.12-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pyyaml-3.12-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pyyaml-debuginfo-3.12-16.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pyyaml-debuginfo-3.12-16.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pyyaml-debuginfo-3.12-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-pyyaml-debuginfo-3.12-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-requests-2.20.0-3.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-requests-2.20.0-3.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-rpm-macros-3-38.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-scipy-1.0.0-21.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-scipy-1.0.0-21.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-scipy-debuginfo-1.0.0-21.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-scipy-debuginfo-1.0.0-21.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-setuptools-39.0.1-13.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-setuptools-wheel-39.0.1-13.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-setuptools_scm-1.15.7-6.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-six-1.11.0-6.module+el8.4.0+403+9ae17a31', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-sqlalchemy-1.3.2-2.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-sqlalchemy-1.3.2-2.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-test-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-test-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-tkinter-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-tkinter-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-tools-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-tools-2.7.18-10.module+el8.6.0+793+57002515.rocky.0.2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-urllib3-1.24.2-3.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-urllib3-1.24.2-3.module+el8.5.0+706+735ec4b3', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-virtualenv-15.1.0-21.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python2-wheel-0.31.1-3.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python2-wheel-wheel-0.31.1-3.module+el8.5.0+706+735ec4b3', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'PyYAML-debugsource-3.12-16.module+el8.4.0+403+9ae17a31', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'PyYAML-debugsource-3.12-16.module+el8.4.0+403+9ae17a31', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'PyYAML-debugsource-3.12-16.module+el8.5.0+706+735ec4b3', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'PyYAML-debugsource-3.12-16.module+el8.5.0+706+735ec4b3', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'scipy-debugsource-1.0.0-21.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'scipy-debugsource-1.0.0-21.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python27:2.7');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Cython-debugsource / PyYAML-debugsource / babel / numpy-debugsource / etc');
}
