#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202402-17.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(190669);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/18");

  script_cve_id(
    "CVE-2022-26691",
    "CVE-2023-4504",
    "CVE-2023-32324",
    "CVE-2023-34241"
  );

  script_name(english:"GLSA-202402-17 : CUPS: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202402-17 (CUPS: Multiple Vulnerabilities)

  - A logic issue was addressed with improved state management. This issue is fixed in Security Update
    2022-003 Catalina, macOS Monterey 12.3, macOS Big Sur 11.6.5. An application may be able to gain elevated
    privileges. (CVE-2022-26691)

  - Due to failure in validating the length provided by an attacker-crafted PPD PostScript document, CUPS and
    libppd are susceptible to a heap-based buffer overflow and possibly code execution. This issue has been
    fixed in CUPS version 2.4.7, released in September of 2023. (CVE-2023-4504)

  - OpenPrinting CUPS is an open source printing system. In versions 2.4.2 and prior, a heap buffer overflow
    vulnerability would allow a remote attacker to launch a denial of service (DoS) attack. A buffer overflow
    vulnerability in the function `format_log_line` could allow remote attackers to cause a DoS on the
    affected system. Exploitation of the vulnerability can be triggered when the configuration file
    `cupsd.conf` sets the value of `loglevel `to `DEBUG`. No known patches or workarounds exist at time of
    publication. (CVE-2023-32324)

  - OpenPrinting CUPS is a standards-based, open source printing system for Linux and other Unix-like
    operating systems. Starting in version 2.0.0 and prior to version 2.4.6, CUPS logs data of free memory to
    the logging service AFTER the connection has been closed, when it should have logged the data right
    before. This is a use-after-free bug that impacts the entire cupsd process. The exact cause of this issue
    is the function `httpClose(con->http)` being called in `scheduler/client.c`. The problem is that httpClose
    always, provided its argument is not null, frees the pointer at the end of the call, only for
    cupsdLogClient to pass the pointer to httpGetHostname. This issue happens in function `cupsdAcceptClient`
    if LogLevel is warn or higher and in two scenarios: there is a double-lookup for the IP Address
    (HostNameLookups Double is set in `cupsd.conf`) which fails to resolve, or if CUPS is compiled with TCP
    wrappers and the connection is refused by rules from `/etc/hosts.allow` and `/etc/hosts.deny`. Version
    2.4.6 has a patch for this issue. (CVE-2023-34241)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202402-17");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=847625");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=907675");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=909018");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=914781");
  script_set_attribute(attribute:"solution", value:
"All CUPS users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-print/cups-2.4.7");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26691");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-34241");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cups");
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
    'name' : 'net-print/cups',
    'unaffected' : make_list("ge 2.4.7"),
    'vulnerable' : make_list("lt 2.4.7")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'CUPS');
}
