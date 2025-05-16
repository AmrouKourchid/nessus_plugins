#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# the CentOS Stream Build Service.
##

include('compat.inc');

if (description)
{
  script_id(191226);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/26");

  script_cve_id(
    "CVE-2022-2127",
    "CVE-2023-3347",
    "CVE-2023-34966",
    "CVE-2023-34967",
    "CVE-2023-34968"
  );
  script_xref(name:"IAVA", value:"2023-A-0376-S");

  script_name(english:"CentOS 9 : samba-4.18.5-100.el9");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates for ctdb.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
samba-4.18.5-100.el9 build changelog.

  - An out-of-bounds read vulnerability was found in Samba due to insufficient length checks in
    winbindd_pam_auth_crap.c. When performing NTLM authentication, the client replies to cryptographic
    challenges back to the server. These replies have variable lengths, and Winbind fails to check the lan
    manager response length. When Winbind is used for NTLM authentication, a maliciously crafted request can
    trigger an out-of-bounds read in Winbind, possibly resulting in a crash. (CVE-2022-2127)

  - A vulnerability was found in Samba's SMB2 packet signing mechanism. The SMB2 packet signing is not
    enforced if an admin configured server signing = required or for SMB2 connections to Domain Controllers
    where SMB2 packet signing is mandatory. This flaw allows an attacker to perform attacks, such as a man-in-
    the-middle attack, by intercepting the network traffic and modifying the SMB2 messages between client and
    server, affecting the integrity of the data. (CVE-2023-3347)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=35021");
  script_set_attribute(attribute:"solution", value:
"Update the CentOS 9 Stream ctdb package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3347");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnetapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-dcerpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-ldb-ldap-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-usershares");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-vfs-iouring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-winexe");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'CentOS 9.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'ctdb-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-devel-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-devel-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-devel-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-dc-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-devel-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-test-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-libs-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-tools-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dc-libs-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dcerpc-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-devel-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-krb5-printing-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ldb-ldap-modules-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-pidl-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-libs-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-tools-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-usershares-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-vfs-iouring-4.18.5-100.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-vfs-iouring-4.18.5-100.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-vfs-iouring-4.18.5-100.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-clients-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-krb5-locator-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-4.18.5-100.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winexe-4.18.5-100.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libnetapi / libnetapi-devel / libsmbclient / etc');
}
