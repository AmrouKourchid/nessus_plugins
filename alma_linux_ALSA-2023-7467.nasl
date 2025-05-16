#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:7467.
##

include('compat.inc');

if (description)
{
  script_id(186293);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/20");

  script_cve_id("CVE-2023-3961", "CVE-2023-4091", "CVE-2023-42669");
  script_xref(name:"ALSA", value:"2023:7467");
  script_xref(name:"IAVA", value:"2023-A-0535");

  script_name(english:"AlmaLinux 8 : samba (ALSA-2023:7467)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:7467 advisory.

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

  - A vulnerability was found in Samba's rpcecho development server, a non-Windows RPC server used to test
    Samba's DCE/RPC stack elements. This vulnerability stems from an RPC function that can be blocked
    indefinitely. The issue arises because the rpcecho service operates with only one worker in the main RPC
    task, allowing calls to the rpcecho server to be blocked for a specified time, causing service
    disruptions. This disruption is triggered by a sleep() call in the dcesrv_echo_TestSleep() function
    under specific conditions. Authenticated users or attackers can exploit this vulnerability to make calls
    to the rpcecho server, requesting it to block for a specified duration, effectively disrupting most
    services and leading to a complete denial of service on the AD DC. The DoS affects all other services as
    rpcecho runs in the main RPC task. (CVE-2023-42669)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-7467.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3961");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 276, 400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnetapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-dcerpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-ldb-ldap-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-usershares");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-vfs-iouring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winexe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'ctdb-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-devel-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-devel-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-devel-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-dc-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-devel-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-test-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-libs-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-tools-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-libs-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dcerpc-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-devel-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-krb5-printing-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ldb-ldap-modules-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-pidl-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-libs-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-tools-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-usershares-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-vfs-iouring-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-clients-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-krb5-locator-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winexe-4.18.6-2.el8_9.alma.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnetapi / libnetapi-devel / libsmbclient / etc');
}
