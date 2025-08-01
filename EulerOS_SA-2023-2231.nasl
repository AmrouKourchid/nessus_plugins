#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177176);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/27");

  script_cve_id(
    "CVE-2021-3670",
    "CVE-2022-2031",
    "CVE-2022-32742",
    "CVE-2022-32743",
    "CVE-2022-32744",
    "CVE-2022-32745",
    "CVE-2022-32746",
    "CVE-2022-42898"
  );
  script_xref(name:"IAVA", value:"2022-A-0495-S");
  script_xref(name:"IAVA", value:"2022-A-0299-S");

  script_name(english:"EulerOS Virtualization 3.0.6.0 : samba (EulerOS-SA-2023-2231)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the samba packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - MaxQueryDuration not honoured in Samba AD DC LDAP (CVE-2021-3670)

  - A flaw was found in Samba. The security vulnerability occurs when KDC and the kpasswd service share a
    single account and set of keys, allowing them to decrypt each other's tickets. A user who has been
    requested to change their password, can exploit this flaw to obtain and use tickets to other services.
    (CVE-2022-2031)

  - A flaw was found in Samba. Some SMB1 write requests were not correctly range-checked to ensure the client
    had sent enough data to fulfill the write, allowing server memory contents to be written into the file (or
    printer) instead of client-supplied data. The client cannot control the area of the server memory written
    to the file (or printer). (CVE-2022-32742)

  - Samba does not validate the Validated-DNS-Host-Name right for the dNSHostName attribute which could permit
    unprivileged users to write it. (CVE-2022-32743)

  - A flaw was found in Samba. The KDC accepts kpasswd requests encrypted with any key known to it. By
    encrypting forged kpasswd requests with its own key, a user can change other users' passwords, enabling
    full domain takeover. (CVE-2022-32744)

  - A flaw was found in Samba. Samba AD users can cause the server to access uninitialized data with an LDAP
    add or modify the request, usually resulting in a segmentation fault. (CVE-2022-32745)

  - A flaw was found in the Samba AD LDAP server. The AD DC database audit logging module can access LDAP
    message values freed by a preceding database module, resulting in a use-after-free issue. This issue is
    only possible when modifying certain privileged attributes, such as userAccountControl. (CVE-2022-32746)

  - PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that
    may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit
    platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other
    platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has 'a similar bug.'
    (CVE-2022-42898)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2231
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?828f76cb");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32745");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42898");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "ctdb-4.9.1-2.h45.eulerosv2r8",
  "ctdb-tests-4.9.1-2.h45.eulerosv2r8",
  "libsmbclient-4.9.1-2.h45.eulerosv2r8",
  "libwbclient-4.9.1-2.h45.eulerosv2r8",
  "python2-samba-4.9.1-2.h45.eulerosv2r8",
  "python2-samba-test-4.9.1-2.h45.eulerosv2r8",
  "python3-samba-4.9.1-2.h45.eulerosv2r8",
  "python3-samba-test-4.9.1-2.h45.eulerosv2r8",
  "samba-4.9.1-2.h45.eulerosv2r8",
  "samba-client-4.9.1-2.h45.eulerosv2r8",
  "samba-client-libs-4.9.1-2.h45.eulerosv2r8",
  "samba-common-4.9.1-2.h45.eulerosv2r8",
  "samba-common-libs-4.9.1-2.h45.eulerosv2r8",
  "samba-common-tools-4.9.1-2.h45.eulerosv2r8",
  "samba-dc-libs-4.9.1-2.h45.eulerosv2r8",
  "samba-krb5-printing-4.9.1-2.h45.eulerosv2r8",
  "samba-libs-4.9.1-2.h45.eulerosv2r8",
  "samba-pidl-4.9.1-2.h45.eulerosv2r8",
  "samba-test-4.9.1-2.h45.eulerosv2r8",
  "samba-test-libs-4.9.1-2.h45.eulerosv2r8",
  "samba-winbind-4.9.1-2.h45.eulerosv2r8",
  "samba-winbind-clients-4.9.1-2.h45.eulerosv2r8",
  "samba-winbind-krb5-locator-4.9.1-2.h45.eulerosv2r8",
  "samba-winbind-modules-4.9.1-2.h45.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
