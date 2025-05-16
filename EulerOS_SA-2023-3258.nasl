#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188849);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id("CVE-2023-4091", "CVE-2023-4154", "CVE-2023-42669");
  script_xref(name:"IAVA", value:"2023-A-0535");

  script_name(english:"EulerOS 2.0 SP11 : samba (EulerOS-SA-2023-3258)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the samba packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - A vulnerability was discovered in Samba, where the flaw allows SMB clients to truncate files, even with
    read-only permissions when the Samba VFS module 'acl_xattr' is configured with 'acl_xattr:ignore system
    acls = yes'. The SMB protocol allows opening files when the client requests read-only access but then
    implicitly truncates the opened file to 0 bytes if the client specifies a separate OVERWRITE create
    disposition request. The issue arises in configurations that bypass kernel file system permissions checks,
    relying solely on Samba's permissions. (CVE-2023-4091)

  - A design flaw was found in Samba's DirSync control implementation, which exposes passwords and secrets in
    Active Directory to privileged users and Read-Only Domain Controllers (RODCs). This flaw allows RODCs and
    users possessing the GET_CHANGES right to access all attributes, including sensitive secrets and
    passwords. Even in a default setup, RODC DC accounts, which should only replicate some passwords, can gain
    access to all domain secrets, including the vital krbtgt, effectively eliminating the RODC / DC
    distinction. Furthermore, the vulnerability fails to account for error conditions (fail open), like out-
    of-memory situations, potentially granting access to secret attributes, even under low-privileged attacker
    influence. (CVE-2023-4154)

  - A vulnerability was found in Samba's 'rpcecho' development server, a non-Windows RPC server used to test
    Samba's DCE/RPC stack elements. This vulnerability stems from an RPC function that can be blocked
    indefinitely. The issue arises because the 'rpcecho' service operates with only one worker in the main RPC
    task, allowing calls to the 'rpcecho' server to be blocked for a specified time, causing service
    disruptions. This disruption is triggered by a 'sleep()' call in the 'dcesrv_echo_TestSleep()' function
    under specific conditions. Authenticated users or attackers can exploit this vulnerability to make calls
    to the 'rpcecho' server, requesting it to block for a specified duration, effectively disrupting most
    services and leading to a complete denial of service on the AD DC. The DoS affects all other services as
    'rpcecho' runs in the main RPC task. (CVE-2023-42669)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3258
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20217ca8");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4154");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-modules");
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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "libsmbclient-4.15.3-4.h22.eulerosv2r11",
  "libwbclient-4.15.3-4.h22.eulerosv2r11",
  "samba-4.15.3-4.h22.eulerosv2r11",
  "samba-client-4.15.3-4.h22.eulerosv2r11",
  "samba-common-4.15.3-4.h22.eulerosv2r11",
  "samba-common-tools-4.15.3-4.h22.eulerosv2r11",
  "samba-libs-4.15.3-4.h22.eulerosv2r11",
  "samba-winbind-4.15.3-4.h22.eulerosv2r11",
  "samba-winbind-clients-4.15.3-4.h22.eulerosv2r11",
  "samba-winbind-modules-4.15.3-4.h22.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
