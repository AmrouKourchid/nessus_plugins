#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2024-087-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192632);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/26");

  script_cve_id(
    "CVE-2024-2004",
    "CVE-2024-2379",
    "CVE-2024-2398",
    "CVE-2024-2466"
  );
  script_xref(name:"IAVA", value:"2024-A-0185-S");

  script_name(english:"Slackware Linux 15.0 / current curl  Multiple Vulnerabilities (SSA:2024-087-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to curl.");
  script_set_attribute(attribute:"description", value:
"The version of curl installed on the remote host is prior to 8.7.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2024-087-01 advisory.

  - When a protocol selection parameter option disables all protocols without adding any then the default set
    of protocols would remain in the allowed set due to an error in the logic for removing protocols. The
    below command would perform a request to curl.se with a plaintext protocol which has been explicitly
    disabled. curl --proto -all,-http http://curl.se The flaw is only present if the set of selected protocols
    disables the entire set of available protocols, in itself a command with no practical use and therefore
    unlikely to be encountered in real situations. The curl security team has thus assessed this to be low
    severity bug. (CVE-2024-2004)

  - libcurl skips the certificate verification for a QUIC connection under certain conditions, when built to
    use wolfSSL. If told to use an unknown/bad cipher or curve, the error path accidentally skips the
    verification and returns OK, thus ignoring any certificate problems. (CVE-2024-2379)

  - When an application tells libcurl it wants to allow HTTP/2 server push, and the amount of received headers
    for the push surpasses the maximum allowed limit (1000), libcurl aborts the server push. When aborting,
    libcurl inadvertently does not free all the previously allocated headers and instead leaks the memory.
    Further, this error condition fails silently and is therefore not easily detected by an application.
    (CVE-2024-2398)

  - libcurl did not check the server certificate of TLS connections done to a host specified as an IP address,
    when built to use mbedTLS. libcurl would wrongly avoid using the set hostname function when the specified
    hostname was given as an IP address, therefore completely skipping the certificate check. This affects all
    uses of TLS protocols (HTTPS, FTPS, IMAPS, POPS3, SMTPS, etc). (CVE-2024-2466)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.372283
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb5d7032");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected curl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2398");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '8.7.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '8.7.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '8.7.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '8.7.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach var constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
