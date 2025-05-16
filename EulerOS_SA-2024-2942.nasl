#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212627);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2023-27043",
    "CVE-2024-0397",
    "CVE-2024-3219",
    "CVE-2024-4032",
    "CVE-2024-6232",
    "CVE-2024-6923",
    "CVE-2024-7592",
    "CVE-2024-8088"
  );

  script_name(english:"EulerOS 2.0 SP12 : python3 (EulerOS-SA-2024-2942)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python3 packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    There is a MEDIUM severity vulnerability affecting CPython.  The  socket module provides a pure-
    Python fallback to the  socket.socketpair() function for platforms that dont support AF_UNIX,  such as
    Windows. This pure-Python implementation uses AF_INET or  AF_INET6 to create a local connected pair of
    sockets. The connection  between the two sockets was not verified before passing the two sockets  back to
    the user, which leaves the server socket vulnerable to a  connection race from a malicious local peer.
    Platforms that support AF_UNIX such as Linux and macOS are not affected by this vulnerability. Versions
    prior to CPython 3.5 are not affected due to the vulnerable API not being included.(CVE-2024-3219)

    There is a MEDIUM severity vulnerability affecting CPython.Regular expressions that allowed excessive
    backtracking during tarfile.TarFile header parsing are vulnerable to ReDoS via specifically-crafted tar
    archives.(CVE-2024-6232)

    There is a HIGH severity vulnerability affecting the CPython 'zipfile' module affecting 'zipfile.Path'.
    Note that the more common API 'zipfile.ZipFile' class is unaffected. When iterating over names of entries
    in a zip archive (for example, methods of 'zipfile.Path' like 'namelist()', 'iterdir()', etc) the process
    can be put into an infinite loop with a maliciously crafted zip archive. This defect applies when reading
    only metadata or extracting the contents of the zip archive. Programs that are not handling user-
    controlled zip archives are not affected.(CVE-2024-8088)

    There is a MEDIUM severity vulnerability affecting CPython.  The  email module didnt properly quote
    newlines for email headers when  serializing an email message allowing for header injection when an email
    is serialized.(CVE-2024-6923)

    There is a LOW severity vulnerability affecting CPython, specifically the 'http.cookies' standard library
    module.   When parsing cookies that contained backslashes for quoted characters in the cookie value, the
    parser would use an algorithm with quadratic complexity, resulting in excess CPU resources being used
    while parsing the value.(CVE-2024-7592)

    A defect was discovered in the Python ssl module where there is a memory race condition with the
    ssl.SSLContext methods cert_store_stats() and get_ca_certs(). The race condition can be
    triggered if the methods are called at the same time as certificates are loaded into the SSLContext, such
    as during the TLS handshake with a certificate directory configured. This issue is fixed in CPython
    3.10.14, 3.11.9, 3.12.3, and 3.13.0a5.(CVE-2024-0397)

    The ipaddress module contained incorrect information about whether certain IPv4 and IPv6 addresses
    were designated as globally reachable or private. This affected the is_private and is_global
    properties of the ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, and
    ipaddress.IPv6Network classes, where values wouldnt be returned in accordance with the latest
    information from the IANA Special-Purpose Address Registries.  CPython 3.12.4 and 3.13.0a6 contain updated
    information from these registries and thus have the intended behavior.(CVE-2024-4032)

    The email module of Python through 3.11.3 incorrectly parses e-mail addresses that contain a special
    character. The wrong portion of an RFC2822 header is identified as the value of the addr-spec. In some
    applications, an attacker can bypass a protection mechanism in which application access is granted only
    after verifying receipt of e-mail to a specific domain (e.g., only @company.example.com addresses may be
    used for signup). This occurs in email/_parseaddr.py in recent versions of Python.(CVE-2023-27043)

Tenable has extracted the preceding description block directly from the EulerOS python3 security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2942
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26dc8390");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27043");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-fgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-unversioned-command");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(12)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "python3-3.9.9-21.h14.eulerosv2r12",
  "python3-fgo-3.9.9-21.h14.eulerosv2r12",
  "python3-unversioned-command-3.9.9-21.h14.eulerosv2r12"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"12", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3");
}
