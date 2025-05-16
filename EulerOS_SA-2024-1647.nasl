#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197234);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id("CVE-2023-38546");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"EulerOS Virtualization 3.0.6.6 : curl (EulerOS-SA-2024-1647)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the curl packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

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
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1647
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63504e14");
  script_set_attribute(attribute:"solution", value:
"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38546");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "curl-7.29.0-46.h29.eulerosv2r7",
  "libcurl-7.29.0-46.h29.eulerosv2r7",
  "libcurl-devel-7.29.0-46.h29.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
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
