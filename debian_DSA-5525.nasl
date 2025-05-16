#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5525. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(182941);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id(
    "CVE-2023-3961",
    "CVE-2023-4091",
    "CVE-2023-4154",
    "CVE-2023-42669",
    "CVE-2023-42670"
  );
  script_xref(name:"IAVA", value:"2023-A-0535");

  script_name(english:"Debian DSA-5525-1 : samba - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5525 advisory.

  - A path traversal vulnerability was identified in Samba when processing client pipe names connecting to
    Unix domain sockets within a private directory. Samba typically uses this mechanism to connect SMB clients
    to remote procedure call (RPC) services like SAMR LSA or SPOOLSS, which Samba initiates on demand.
    However, due to inadequate sanitization of incoming client pipe names, allowing a client to send a pipe
    name containing Unix directory traversal characters (../). This could result in SMB clients connecting as
    root to Unix domain sockets outside the private directory. If an attacker or client managed to send a pipe
    name resolving to an external service using an existing Unix domain socket, it could potentially lead to
    unauthorized access to the service and consequential adverse events, including compromise or service
    crashes. (CVE-2023-3961)

  - A vulnerability was discovered in Samba, where the flaw allows SMB clients to truncate files, even with
    read-only permissions when the Samba VFS module acl_xattr is configured with acl_xattr:ignore system
    acls = yes. The SMB protocol allows opening files when the client requests read-only access but then
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

  - A vulnerability was found in Samba's rpcecho development server, a non-Windows RPC server used to test
    Samba's DCE/RPC stack elements. This vulnerability stems from an RPC function that can be blocked
    indefinitely. The issue arises because the rpcecho service operates with only one worker in the main RPC
    task, allowing calls to the rpcecho server to be blocked for a specified time, causing service
    disruptions. This disruption is triggered by a sleep() call in the dcesrv_echo_TestSleep() function
    under specific conditions. Authenticated users or attackers can exploit this vulnerability to make calls
    to the rpcecho server, requesting it to block for a specified duration, effectively disrupting most
    services and leading to a complete denial of service on the AD DC. The DoS affects all other services as
    rpcecho runs in the main RPC task. (CVE-2023-42669)

  - A flaw was found in Samba. It is susceptible to a vulnerability where multiple incompatible RPC listeners
    can be initiated, causing disruptions in the AD DC service. When Samba's RPC server experiences a high
    load or unresponsiveness, servers intended for non-AD DC purposes (for example, NT4-emulation classic
    DCs) can erroneously start and compete for the same unix domain sockets. This issue leads to partial
    query responses from the AD DC, causing issues such as The procedure number is out of range when using
    tools like Active Directory Users. This flaw allows an attacker to disrupt AD DC services.
    (CVE-2023-42670)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/samba");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5525");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-3961");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4091");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4154");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-42669");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-42670");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/samba");
  script_set_attribute(attribute:"solution", value:
"Upgrade the samba packages.

For the stable distribution (bookworm), these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3961");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:registry-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-ad-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-ad-provision");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-common-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba-vfs-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'ctdb', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libnss-winbind', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libpam-winbind', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libsmbclient', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libsmbclient-dev', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libwbclient-dev', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libwbclient0', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'python3-samba', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'registry-tools', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'samba', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'samba-ad-dc', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'samba-ad-provision', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'samba-common', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'samba-common-bin', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'samba-dev', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'samba-dsdb-modules', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'samba-libs', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'samba-testsuite', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'samba-vfs-modules', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'smbclient', 'reference': '2:4.17.12+dfsg-0+deb12u1'},
    {'release': '12.0', 'prefix': 'winbind', 'reference': '2:4.17.12+dfsg-0+deb12u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnss-winbind / etc');
}
