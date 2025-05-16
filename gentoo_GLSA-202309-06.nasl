#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202309-06.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(181514);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id(
    "CVE-2007-4559",
    "CVE-2016-2124",
    "CVE-2020-17049",
    "CVE-2020-25717",
    "CVE-2020-25718",
    "CVE-2020-25719",
    "CVE-2020-25721",
    "CVE-2020-25722",
    "CVE-2021-3670",
    "CVE-2021-3738",
    "CVE-2021-20251",
    "CVE-2021-20316",
    "CVE-2021-23192",
    "CVE-2021-44141",
    "CVE-2021-44142",
    "CVE-2022-0336",
    "CVE-2022-1615",
    "CVE-2022-2031",
    "CVE-2022-3437",
    "CVE-2022-3592",
    "CVE-2022-32742",
    "CVE-2022-32743",
    "CVE-2022-32744",
    "CVE-2022-32745",
    "CVE-2022-32746",
    "CVE-2022-37966",
    "CVE-2022-37967",
    "CVE-2022-38023",
    "CVE-2022-42898",
    "CVE-2022-45141",
    "CVE-2023-0225",
    "CVE-2023-0614",
    "CVE-2023-0922"
  );

  script_name(english:"GLSA-202309-06 : Samba: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202309-06 (Samba: Multiple Vulnerabilities)

  - Directory traversal vulnerability in the (1) extract and (2) extractall functions in the tarfile module in
    Python allows user-assisted remote attackers to overwrite arbitrary files via a .. (dot dot) sequence in
    filenames in a TAR archive, a related issue to CVE-2001-1267. (CVE-2007-4559)

  - A flaw was found in the way samba implemented SMB1 authentication. An attacker could use this flaw to
    retrieve the plaintext password sent over the wire even if Kerberos authentication was required.
    (CVE-2016-2124)

  - Kerberos Security Feature Bypass Vulnerability (CVE-2020-17049)

  - A flaw was found in the way Samba maps domain users to local users. An authenticated attacker could use
    this flaw to cause possible privilege escalation. (CVE-2020-25717)

  - A flaw was found in the way samba, as an Active Directory Domain Controller, is able to support an RODC
    (read-only domain controller). This would allow an RODC to print administrator tickets. (CVE-2020-25718)

  - A flaw was found in the way Samba, as an Active Directory Domain Controller, implemented Kerberos name-
    based authentication. The Samba AD DC, could become confused about the user a ticket represents if it did
    not strictly require a Kerberos PAC and always use the SIDs found within. The result could include total
    domain compromise. (CVE-2020-25719)

  - Kerberos acceptors need easy access to stable AD identifiers (eg objectSid). Samba as an AD DC now
    provides a way for Linux applications to obtain a reliable SID (and samAccountName) in issued tickets.
    (CVE-2020-25721)

  - Multiple flaws were found in the way samba AD DC implemented access and conformance checking of stored
    data. An attacker could use this flaw to cause total domain compromise. (CVE-2020-25722)

  - MaxQueryDuration not honoured in Samba AD DC LDAP (CVE-2021-3670)

  - In DCE/RPC it is possible to share the handles (cookies for resource state) between multiple connections
    via a mechanism called 'association groups'. These handles can reference connections to our sam.ldb
    database. However while the database was correctly shared, the user credentials state was only pointed at,
    and when one connection within that association group ended, the database would be left pointing at an
    invalid 'struct session_info'. The most likely outcome here is a crash, but it is possible that the use-
    after-free could instead allow different user state to be pointed at and this might allow more privileged
    access. (CVE-2021-3738)

  - A flaw was found in samba. A race condition in the password lockout code may lead to the risk of brute
    force attacks being successful if special conditions are met. (CVE-2021-20251)

  - A flaw was found in the way Samba handled file/directory metadata. This flaw allows an authenticated
    attacker with permissions to read or modify share metadata, to perform this operation outside of the
    share. (CVE-2021-20316)

  - A flaw was found in the way samba implemented DCE/RPC. If a client to a Samba server sent a very large
    DCE/RPC request, and chose to fragment it, an attacker could replace later fragments with their own data,
    bypassing the signature requirements. (CVE-2021-23192)

  - All versions of Samba prior to 4.15.5 are vulnerable to a malicious client using a server symlink to
    determine if a file or directory exists in an area of the server file system not exported under the share
    definition. SMB1 with unix extensions has to be enabled in order for this attack to succeed.
    (CVE-2021-44141)

  - The Samba vfs_fruit module uses extended file attributes (EA, xattr) to provide ...enhanced compatibility
    with Apple SMB clients and interoperability with a Netatalk 3 AFP fileserver. Samba versions prior to
    4.13.17, 4.14.12 and 4.15.5 with vfs_fruit configured allow out-of-bounds heap read and write via
    specially crafted extended file attributes. A remote attacker with write access to extended file
    attributes can execute arbitrary code with the privileges of smbd, typically root. (CVE-2021-44142)

  - The Samba AD DC includes checks when adding service principals names (SPNs) to an account to ensure that
    SPNs do not alias with those already in the database. Some of these checks are able to be bypassed if an
    account modification re-adds an SPN that was previously present on that account, such as one added when a
    computer is joined to a domain. An attacker who has the ability to write to an account can exploit this to
    perform a denial-of-service attack by adding an SPN that matches an existing service. Additionally, an
    attacker who can intercept traffic can impersonate existing services, resulting in a loss of
    confidentiality and integrity. (CVE-2022-0336)

  - In Samba, GnuTLS gnutls_rnd() can fail and give predictable random values. (CVE-2022-1615)

  - A flaw was found in Samba. The security vulnerability occurs when KDC and the kpasswd service share a
    single account and set of keys, allowing them to decrypt each other's tickets. A user who has been
    requested to change their password, can exploit this flaw to obtain and use tickets to other services.
    (CVE-2022-2031)

  - A heap-based buffer overflow vulnerability was found in Samba within the GSSAPI unwrap_des() and
    unwrap_des3() routines of Heimdal. The DES and Triple-DES decryption routines in the Heimdal GSSAPI
    library allow a length-limited write buffer overflow on malloc() allocated memory when presented with a
    maliciously small packet. This flaw allows a remote user to send specially crafted malicious data to the
    application, possibly resulting in a denial of service (DoS) attack. (CVE-2022-3437)

  - A symlink following vulnerability was found in Samba, where a user can create a symbolic link that will
    make 'smbd' escape the configured share path. This flaw allows a remote user with access to the exported
    part of the file system under a share via SMB1 unix extensions or NFS to create symlinks to files outside
    the 'smbd' configured share path and gain access to another restricted server's filesystem.
    (CVE-2022-3592)

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

  - Windows Kerberos RC4-HMAC Elevation of Privilege Vulnerability (CVE-2022-37966)

  - Windows Kerberos Elevation of Privilege Vulnerability (CVE-2022-37967)

  - Netlogon RPC Elevation of Privilege Vulnerability (CVE-2022-38023)

  - PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that
    may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit
    platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other
    platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has a similar bug.
    (CVE-2022-42898)

  - Since the Windows Kerberos RC4-HMAC Elevation of Privilege Vulnerability was disclosed by Microsoft on Nov
    8 2022 and per RFC8429 it is assumed that rc4-hmac is weak, Vulnerable Samba Active Directory DCs will
    issue rc4-hmac encrypted tickets despite the target server supporting better encryption (eg aes256-cts-
    hmac-sha1-96). (CVE-2022-45141)

  - A flaw was found in Samba. An incomplete access check on dnsHostName allows authenticated but otherwise
    unprivileged users to delete this attribute from any object in the directory. (CVE-2023-0225)

  - The fix in 4.6.16, 4.7.9, 4.8.4 and 4.9.7 for CVE-2018-10919 Confidential attribute disclosure vi LDAP
    filters was insufficient and an attacker may be able to obtain confidential BitLocker recovery keys from a
    Samba AD DC. (CVE-2023-0614)

  - The Samba AD DC administration tool, when operating against a remote LDAP server, will by default send new
    or reset passwords over a signed-only connection. (CVE-2023-0922)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202309-06");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=820566");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=821688");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=830983");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=832433");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=861512");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=866225");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=869122");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=878273");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=880437");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=886153");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=903621");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=905320");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=910334");
  script_set_attribute(attribute:"solution", value:
"All Samba users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-fs/samba-4.18.4");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44142");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-45141");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'unaffected' : make_list("ge 4.18.4"),
    'vulnerable' : make_list("lt 4.18.4")
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
