#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202543);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/27");

  script_cve_id(
    "CVE-2024-2961",
    "CVE-2024-33599",
    "CVE-2024-33600",
    "CVE-2024-33601",
    "CVE-2024-33602"
  );
  script_xref(name:"IAVA", value:"2025-A-0062");

  script_name(english:"EulerOS 2.0 SP9 : glibc (EulerOS-SA-2024-1959)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to
    it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to
    crash an application or overwrite a neighbouring variable.(CVE-2024-2961)

    nscd: Stack-based buffer overflow in netgroup cache.If the Name Service Cache Daemon's (nscd) fixed size
    cache is exhausted by client requests then a subsequent client request for netgroup data may result in a
    stack-based buffer overflow.  This flaw was introduced in glibc 2.15 when the cache was added to nscd.This
    vulnerability is only present in the nscd binary.(CVE-2024-33599)

    nscd: netgroup cache may terminate daemon on memory allocation failure.The Name Service Cache Daemon's
    (nscd) netgroup cache uses xmalloc or xrealloc and these functions may terminate the process due to a
    memory allocation failure resulting in a denial of service to the clients.  The flaw was introduced in
    glibc 2.15 when the cache was added to nscd.This vulnerability is only present in the nscd
    binary.(CVE-2024-33601)

    nscd: Null pointer crashes after notfound response.If the Name Service Cache Daemon's (nscd) cache fails
    to add a not-found netgroup response to the cache, the client request can result in a null pointer
    dereference.  This flaw was introduced in glibc 2.15 when the cache was added to nscd.This vulnerability
    is only present in the nscd binary.(CVE-2024-33600)

    nscd: netgroup cache assumes NSS callback uses in-buffer strings.The Name Service Cache Daemon's (nscd)
    netgroup cache can corrupt memory when the NSS callback does not store all strings in the provided
    buffer.The flaw was introduced in glibc 2.15 when the cache was added to nscd.This vulnerability is only
    present in the nscd binary.(CVE-2024-33602)

Tenable has extracted the preceding description block directly from the EulerOS glibc security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1959
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cee1fca0");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-33602");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-33599");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CosmicSting: Magento Arbitrary File Read (CVE-2024-34102) + PHP Buffer Overflow in the iconv() function of glibc (CVE-2024-2961)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-debugutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-locale-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "glibc-2.28-61.h49.eulerosv2r9",
  "glibc-all-langpacks-2.28-61.h49.eulerosv2r9",
  "glibc-common-2.28-61.h49.eulerosv2r9",
  "glibc-debugutils-2.28-61.h49.eulerosv2r9",
  "glibc-locale-source-2.28-61.h49.eulerosv2r9",
  "libnsl-2.28-61.h49.eulerosv2r9",
  "nscd-2.28-61.h49.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
