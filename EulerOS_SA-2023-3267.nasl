#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189066);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/17");

  script_cve_id("CVE-2023-38545", "CVE-2023-38546");
  script_xref(name:"IAVA", value:"2023-A-0531-S");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"EulerOS 2.0 SP11 : curl (EulerOS-SA-2023-3267)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the curl packages installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

  - This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake. When curl is asked to
    pass along the host name to the SOCKS5 proxy to allow that to resolve the address instead of it getting
    done by curl itself, the maximum length that host name can be is 255 bytes. If the host name is detected
    to be longer, curl switches to local name resolving and instead passes on the resolved address only. Due
    to this bug, the local variable that means 'let the host resolve the name' could get the wrong value
    during a slow SOCKS5 handshake, and contrary to the intention, copy the too long host name to the target
    buffer instead of copying just the resolved address there. The target buffer being a heap based buffer,
    and the host name coming from the URL that curl has been told to operate with. (CVE-2023-38545)

  - CVE-2023-38545 is a heap-based buffer overflow vulnerability in the SOCKS5 proxy handshake in libcurl and
    curl.  When curl is given a hostname to pass along to a SOCKS5 proxy that is greater than 255 bytes in
    length, it will switch to local name resolution in order to resolve the address before passing it on to
    the SOCKS5 proxy. However, due to a bug introduced in 2020, this local name resolution could fail due to a
    slow SOCKS5 handshake, causing curl to pass on the hostname greater than 255 bytes in length into the
    target buffer, leading to a heap overflow.  The advisory for CVE-2023-38545 gives an example exploitation
    scenario of a malicious HTTPS server redirecting to a specially crafted URL. While it might seem that an
    attacker would need to influence the slowness of the SOCKS5 handshake, the advisory states that server
    latency is likely slow enough to trigger this bug. (CVE-2023-38545)

  - This flaw allows an attacker to insert cookies at will into a running program using libcurl, if the
    specific series of conditions are met. libcurl performs transfers. In its API, an application creates
    'easy handles' that are the individual handles for single transfers. libcurl provides a function call that
    duplicates en easy handle called
    [curl_easy_duphandle](https://curl.se/libcurl/c/curl_easy_duphandle.html). If a transfer has cookies
    enabled when the handle is duplicated, the cookie-enable state is also cloned - but without cloning the
    actual cookies. If the source handle did not read any cookies from a specific file on disk, the cloned
    version of the handle would instead store the file name as `none` (using the four ASCII letters, no
    quotes). Subsequent use of the cloned handle that does not explicitly set a source to load cookies from
    would then inadvertently load cookies from a file named `none` - if such a file exists and is readable in
    the current directory of the program using libcurl. And if using the correct file format of course.
    (CVE-2023-38546)

  - CVE-2023-38546 is a cookie injection vulnerability in the curl_easy_duphandle(), a function in libcurl
    that duplicates easy handles.  When duplicating an easy handle, if cookies are enabled, the duplicated
    easy handle will not duplicate the cookies themselves, but would instead set the filename to none.'
    Therefore, when the duplicated easy handle is subsequently used, if a source was not set for the cookies,
    libcurl would attempt to load them from the file named none' on the disk.  This vulnerability is rated
    low, as the various conditions required for exploitation are unlikely.  (CVE-2023-38546)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3267
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c455a1c8");
  script_set_attribute(attribute:"solution", value:
"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcurl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "curl-7.79.1-2.h25.eulerosv2r11",
  "libcurl-7.79.1-2.h25.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl");
}
