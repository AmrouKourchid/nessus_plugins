#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206521);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id("CVE-2024-2511");

  script_name(english:"EulerOS Virtualization 2.12.1 : openssl (EulerOS-SA-2024-2314)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

    Issue summary: Some non-default TLS server configurations can cause unbounded memory growth when
    processing TLSv1.3 sessions Impact summary: An attacker may exploit certain server configurations to
    trigger unbounded memory growth that would lead to a Denial of Service This problem can occur in TLSv1.3
    if the non-default SSL_OP_NO_TICKET option is being used (but not if early_data support is also configured
    and the default anti-replay protection is in use). In this case, under certain conditions, the session
    cache can get into an incorrect state and it will fail to flush properly as it fills. The session cache
    will continue to grow in an unbounded manner. A malicious client could deliberately create the scenario
    for this failure to force a Denial of Service. It may also happen by accident in normal operation. This
    issue only affects TLS servers supporting TLSv1.3. It does not affect TLS clients. The FIPS modules in
    3.2, 3.1 and 3.0 are not affected by this issue. OpenSSL 1.0.2 is also not affected by this
    issue.(CVE-2024-2511)

Tenable has extracted the preceding description block directly from the EulerOS Virtualization openssl security
advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2314
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6066aac");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2511");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-1.1.1m");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-libs-1.1.1m");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-perl-1.1.1m");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.12.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.12.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.12.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "openssl-1.1.1m-15.h38.eulerosv2r12",
  "openssl-libs-1.1.1m-15.h38.eulerosv2r12",
  "openssl-perl-1.1.1m-15.h38.eulerosv2r12"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
