#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202405-01.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(194974);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/04");

  script_cve_id(
    "CVE-2023-6507",
    "CVE-2023-6597",
    "CVE-2023-24329",
    "CVE-2023-40217",
    "CVE-2023-41105",
    "CVE-2024-0450"
  );

  script_name(english:"GLSA-202405-01 : Python, PyPy3: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202405-01 (Python, PyPy3: Multiple Vulnerabilities)

  - An issue was found in CPython 3.12.0 `subprocess` module on POSIX platforms. The issue was fixed in
    CPython 3.12.1 and does not affect other stable releases. When using the `extra_groups=` parameter with an
    empty list as a value (ie `extra_groups=[]`) the logic regressed to not call `setgroups(0, NULL)` before
    calling `exec()`, thus not dropping the original processes' groups before starting the new process. There
    is no issue when the parameter isn't used or when any value is used besides an empty list. This issue only
    impacts CPython processes run with sufficient privilege to make the `setgroups` system call (typically
    `root`). (CVE-2023-6507)

  - An issue was found in the CPython `tempfile.TemporaryDirectory` class affecting versions 3.12.1, 3.11.7,
    3.10.13, 3.9.18, and 3.8.18 and prior. The tempfile.TemporaryDirectory class would dereference symlinks
    during cleanup of permissions-related errors. This means users which can run privileged programs are
    potentially able to modify permissions of files referenced by symlinks in some circumstances.
    (CVE-2023-6597)

  - An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting
    methods by supplying a URL that starts with blank characters. (CVE-2023-24329)

  - An issue was discovered in Python before 3.8.18, 3.9.x before 3.9.18, 3.10.x before 3.10.13, and 3.11.x
    before 3.11.5. It primarily affects servers (such as HTTP servers) that use TLS client authentication. If
    a TLS server-side socket is created, receives data into the socket buffer, and then is closed quickly,
    there is a brief window where the SSLSocket instance will detect the socket as not connected and won't
    initiate a handshake, but buffered data will still be readable from the socket buffer. This data will not
    be authenticated if the server-side TLS peer is expecting client certificate authentication, and is
    indistinguishable from valid TLS stream data. Data is limited in size to the amount that will fit in the
    buffer. (The TLS connection cannot directly be used for data exfiltration because the vulnerable code path
    requires that the connection be closed on initialization of the SSLSocket.) (CVE-2023-40217)

  - An issue was discovered in Python 3.11 through 3.11.4. If a path containing '\0' bytes is passed to
    os.path.normpath(), the path will be truncated unexpectedly at the first '\0' byte. There are plausible
    cases in which an application would have rejected a filename for security reasons in Python 3.10.x or
    earlier, but that filename is no longer rejected in Python 3.11.x. (CVE-2023-41105)

  - An issue was found in the CPython `zipfile` module affecting versions 3.12.1, 3.11.7, 3.10.13, 3.9.18, and
    3.8.18 and prior. The zipfile module is vulnerable to quoted-overlap zip-bombs which exploit the zip
    format to create a zip-bomb with a high compression ratio. The fixed versions of CPython makes the zipfile
    module reject zip archives which overlap entries in the archive. (CVE-2024-0450)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202405-01");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=884653");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=897958");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=908018");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=912976");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=919475");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=927299");
  script_set_attribute(attribute:"solution", value:
"All Python, PyPy3 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-lang/python-3.12.1:3.12
          # emerge --ask --oneshot --verbose >=dev-lang/python-3.11.9:3.11
          # emerge --ask --oneshot --verbose >=dev-lang/python-3.10.14:3.10
          # emerge --ask --oneshot --verbose >=dev-lang/python-3.9.19:3.9
          # emerge --ask --oneshot --verbose >=dev-lang/python-3.8.19:3.8
          # emerge --ask --oneshot --verbose >=dev-python/pypy3-7.3.16
          # emerge --ask --oneshot --verbose >=dev-python/pypy3_10-7.3.16
          # emerge --ask --oneshot --verbose >=dev-python/pypy3_9-7.3.16");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41105");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pypy3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pypy3_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pypy3_9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'dev-lang/python',
    'unaffected' : make_list("ge 3.10.14", "lt 3.10.0"),
    'vulnerable' : make_list("lt 3.10.14")
  },
  {
    'name' : 'dev-lang/python',
    'unaffected' : make_list("ge 3.11.8", "lt 3.11.0"),
    'vulnerable' : make_list("lt 3.11.8")
  },
  {
    'name' : 'dev-lang/python',
    'unaffected' : make_list("ge 3.12.1", "lt 3.12.0"),
    'vulnerable' : make_list("lt 3.12.1")
  },
  {
    'name' : 'dev-lang/python',
    'unaffected' : make_list("ge 3.8.19", "lt 3.8.0"),
    'vulnerable' : make_list("lt 3.8.19")
  },
  {
    'name' : 'dev-lang/python',
    'unaffected' : make_list("ge 3.9.19", "lt 3.9.0"),
    'vulnerable' : make_list("lt 3.9.19")
  },
  {
    'name' : 'dev-python/pypy3',
    'unaffected' : make_list("ge 7.3.16"),
    'vulnerable' : make_list("lt 7.3.16")
  },
  {
    'name' : 'dev-python/pypy3_10',
    'unaffected' : make_list("ge 7.3.16"),
    'vulnerable' : make_list("lt 7.3.16")
  },
  {
    'name' : 'dev-python/pypy3_9',
    'unaffected' : make_list("ge 7.3.16"),
    'vulnerable' : make_list("lt 7.3.16")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Python / PyPy3');
}
