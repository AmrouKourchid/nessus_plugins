#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188760);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2022-2127",
    "CVE-2023-34966",
    "CVE-2023-34967",
    "CVE-2023-34968"
  );
  script_xref(name:"IAVA", value:"2023-A-0376-S");

  script_name(english:"EulerOS 2.0 SP11 : samba (EulerOS-SA-2023-2852)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the samba packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - An out-of-bounds read vulnerability was found in Samba due to insufficient length checks in
    winbindd_pam_auth_crap.c. When performing NTLM authentication, the client replies to cryptographic
    challenges back to the server. These replies have variable lengths, and Winbind fails to check the lan
    manager response length. When Winbind is used for NTLM authentication, a maliciously crafted request can
    trigger an out-of-bounds read in Winbind, possibly resulting in a crash. (CVE-2022-2127)

  - An infinite loop vulnerability was found in Samba's mdssvc RPC service for Spotlight. When parsing
    Spotlight mdssvc RPC packets sent by the client, the core unmarshalling function sl_unpack_loop() did not
    validate a field in the network packet that contains the count of elements in an array-like structure. By
    passing 0 as the count value, the attacked function will run in an endless loop consuming 100% CPU. This
    flaw allows an attacker to issue a malformed RPC request, triggering an infinite loop, resulting in a
    denial of service condition. (CVE-2023-34966)

  - A Type Confusion vulnerability was found in Samba's mdssvc RPC service for Spotlight. When parsing
    Spotlight mdssvc RPC packets, one encoded data structure is a key-value style dictionary where the keys
    are character strings, and the values can be any of the supported types in the mdssvc protocol. Due to a
    lack of type checking in callers of the dalloc_value_for_key() function, which returns the object
    associated with a key, a caller may trigger a crash in talloc_get_size() when talloc detects that the
    passed-in pointer is not a valid talloc pointer. With an RPC worker process shared among multiple client
    connections, a malicious client or attacker can trigger a process crash in a shared RPC mdssvc worker
    process, affecting all other clients this worker serves. (CVE-2023-34967)

  - A path disclosure vulnerability was found in Samba. As part of the Spotlight protocol, Samba discloses the
    server-side absolute path of shares, files, and directories in the results for search queries. This flaw
    allows a malicious client or an attacker with a targeted RPC request to view the information that is part
    of the disclosed path. (CVE-2023-34968)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2852
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6fff0be");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34968");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/20");
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
  "libsmbclient-4.15.3-4.h20.eulerosv2r11",
  "libwbclient-4.15.3-4.h20.eulerosv2r11",
  "samba-4.15.3-4.h20.eulerosv2r11",
  "samba-client-4.15.3-4.h20.eulerosv2r11",
  "samba-common-4.15.3-4.h20.eulerosv2r11",
  "samba-common-tools-4.15.3-4.h20.eulerosv2r11",
  "samba-libs-4.15.3-4.h20.eulerosv2r11",
  "samba-winbind-4.15.3-4.h20.eulerosv2r11",
  "samba-winbind-clients-4.15.3-4.h20.eulerosv2r11",
  "samba-winbind-modules-4.15.3-4.h20.eulerosv2r11"
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
