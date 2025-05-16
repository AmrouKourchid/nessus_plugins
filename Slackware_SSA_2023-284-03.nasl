#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-284-03. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182877);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/14");

  script_cve_id(
    "CVE-2023-3961",
    "CVE-2023-4091",
    "CVE-2023-4154",
    "CVE-2023-42669",
    "CVE-2023-42670"
  );
  script_xref(name:"IAVA", value:"2023-A-0535");

  script_name(english:"Slackware Linux 15.0 / current samba  Multiple Vulnerabilities (SSA:2023-284-03)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to samba.");
  script_set_attribute(attribute:"description", value:
"The version of samba installed on the remote host is prior to 4.18.8 / 4.19.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2023-284-03 advisory.

  - The SMB 1/2/3 protocols allow clients to connect to named pipes via the IPC$ (Inter-Process Communication)
    share for the process of inter-process communication between SMB clients and servers. Since Samba 4.16.0,
    Samba internally connects client pipe names to unix domain sockets within a private directory, allowing
    clients to connect to services listening on those sockets. This is usually used to connect SMB clients to
    remote proceedure call (RPC) services, such as SAMR LSA, or SPOOLSS, which Samba starts on demand.
    However, insufficient sanitization was done on the incoming client pipe name, meaning that a client
    sending a pipe name containing unix directory traversal characters (../) could cause Samba to connect to
    unix domain sockets outside of the private directory meant to restrict the services a client could connect
    to. Samba connects to the unix domain sockets as root, meaning if a client could send a pipe name that
    resolved to an external service using an existing unix domain socket, the client would be able to connect
    to it without filesystem permissions restricting access. Depending on the service the client can connect
    to, the client may be able to trigger adverse events such as denial of service, crashing the service, or
    potentially compromising it. There are no current known exploits for this bug. (CVE-2023-3961)

  - The SMB protocol allows opening files where the client requests read-only access, but then implicitly
    truncating the opened file if the client specifies a separate OVERWRITE create disposition. This operation
    requires write access to the file, and in the default Samba configuration the operating system kernel will
    deny access to open a read-only file for read/write (which the truncate operation requires). However, when
    Samba has been configured to ignore kernel file system permissions, Samba will truncate a file when the
    underlying operating system kernel would deny the operation. Affected Samba configurations are the ones
    where kernel file-system permission checks are bypassed, relying on Samba's own permission enforcement.
    The error is that this check is done against the client request for read-only access, and not the
    implicitly requested read-write (for truncate) one. The widely used Samba VFS module acl_xattr when
    configured with the module configuration parameter acl_xattr:ignore system acls = yes is the only
    upstream Samba module that allows this behavior and is the only known method of reproducing this security
    flaw. If (as is the default) the module configuration parameter acl_xattr:ignore system acls=no, then
    the Samba server is not vulnerable to this attack. (CVE-2023-4091)

  - In normal operation, passwords and (most) secrets are never disclosed over LDAP in Active Directory.
    However, due to a design flaw in Samba's implementation of the DirSync control, Active Directory accounts
    authorized to do some replication, but not to replicate sensitive attributes, can instead replicate
    critical domain passwords and secrets. In a default installation, this means that RODC DC accounts (which
    should only be permitted to replicate some passwords) can instead obtain all domain secrets, including the
    core AD secret: the krbtgt password. RODCs are given this permission as part of their installation for DRS
    replication. This vulnerability removes the RODC / DC distinction. Secondly, and just as problematically,
    the access check for this functionality did not account for error conditions - errors like out of memory
    were regarded as success. This is sometimes described as fail open. In these error conditions, some of
    which (eg out of memory) may be influenced by a low-privileged attacker, access to the secret attributes
    could be obtained! (CVE-2023-4154)

  - Samba developers have built a non-Windows RPC server known as rpcecho to test elements of the Samba
    DCE/RPC stack under their full control. One RPC function provided by rpcecho can block, essentially
    indefinitely, and because the rpcecho service is provided from the main RPC task, which has only one
    worker, this denies essentially all service on the AD DC. To address this problem, the rpcecho server is
    removed from our production binaries and is restricted to selftest builds only. (CVE-2023-42669)

  - Samba as an Active Directory DC operates RPC services from two distinct parts of the codebase. Those
    services focused on the AD DC are started in the main samba process, while services focused on the
    fileserver and NT4-like DC are started from the new samba-dcerpcd, which is launched on-demand from the
    fileserver (smbd) tasks. When starting, samba-dcerpcd must first confirm which services not to provide, so
    as to avoid duplicate listeners. The issue in this advisory is that, when Samba's RPC server is under
    load, or otherwise not responding, the servers NOT built for the AD DC (eg build instead for the
    NT4-emulation classic DCs) can be incorrectly started, and compete to listen on the same unix domain
    sockets. This then results in some queries being answered by the AD DC, and some not. This has been seen
    in production at multiple sites, as The procedure number is out of range when starting Active Directory
    Users and Computers tool, however it can also be triggered maliciously, to prevent service on the AD DC.
    (CVE-2023-42670)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.440518
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43c806b4");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected samba package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3961");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { 'fixed_version' : '4.18.8', 'product' : 'samba', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '4.18.8', 'product' : 'samba', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '4.19.1', 'product' : 'samba', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '4.19.1', 'product' : 'samba', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
