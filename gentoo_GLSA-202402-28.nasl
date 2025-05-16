#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202402-28.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(190761);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/20");

  script_cve_id(
    "CVE-2018-14628",
    "CVE-2022-2127",
    "CVE-2023-3347",
    "CVE-2023-3961",
    "CVE-2023-4091",
    "CVE-2023-4154",
    "CVE-2023-34966",
    "CVE-2023-34967",
    "CVE-2023-34968",
    "CVE-2023-42669",
    "CVE-2023-42670"
  );

  script_name(english:"GLSA-202402-28 : Samba: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202402-28 (Samba: Multiple Vulnerabilities)

  - An information leak vulnerability was discovered in Samba's LDAP server. Due to missing access control
    checks, an authenticated but unprivileged attacker could discover the names and preserved attributes of
    deleted objects in the LDAP store. (CVE-2018-14628)

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
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202402-28");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=891267");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=910606");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=915556");
  script_set_attribute(attribute:"solution", value:
"All Samba users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-fs/samba-4.18.9");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3961");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'net-fs/samba',
    'unaffected' : make_list("ge 4.18.9"),
    'vulnerable' : make_list("lt 4.18.9")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Samba');
}
