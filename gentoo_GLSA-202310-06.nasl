#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202310-06.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(182758);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/22");

  script_cve_id(
    "CVE-2019-14870",
    "CVE-2021-44758",
    "CVE-2022-3437",
    "CVE-2022-3671",
    "CVE-2022-41916",
    "CVE-2022-42898",
    "CVE-2022-44640",
    "CVE-2022-44758",
    "CVE-2022-45142"
  );

  script_name(english:"GLSA-202310-06 : Heimdal: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202310-06 (Heimdal: Multiple Vulnerabilities)

  - All Samba versions 4.x.x before 4.9.17, 4.10.x before 4.10.11 and 4.11.x before 4.11.3 have an issue,
    where the S4U (MS-SFU) Kerberos delegation model includes a feature allowing for a subset of clients to be
    opted out of constrained delegation in any way, either S4U2Self or regular Kerberos authentication, by
    forcing all tickets for these clients to be non-forwardable. In AD this is implemented by a user attribute
    delegation_not_allowed (aka not-delegated), which translates to disallow-forwardable. However the Samba AD
    DC does not do that for S4U2Self and does set the forwardable flag even if the impersonated client has the
    not-delegated flag set. (CVE-2019-14870)

  - Heimdal before 7.7.1 allows attackers to cause a NULL pointer dereference in a SPNEGO acceptor via a
    preferred_mech_type of GSS_C_NO_OID and a nonzero initial_response value to send_accept. (CVE-2021-44758)

  - A heap-based buffer overflow vulnerability was found in Samba within the GSSAPI unwrap_des() and
    unwrap_des3() routines of Heimdal. The DES and Triple-DES decryption routines in the Heimdal GSSAPI
    library allow a length-limited write buffer overflow on malloc() allocated memory when presented with a
    maliciously small packet. This flaw allows a remote user to send specially crafted malicious data to the
    application, possibly resulting in a denial of service (DoS) attack. (CVE-2022-3437)

  - A vulnerability classified as critical was found in SourceCodester eLearning System 1.0. This
    vulnerability affects unknown code of the file /admin/students/manage.php. The manipulation of the
    argument id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed
    to the public and may be used. VDB-212014 is the identifier assigned to this vulnerability.
    (CVE-2022-3671)

  - Heimdal is an implementation of ASN.1/DER, PKIX, and Kerberos. Versions prior to 7.7.1 are vulnerable to a
    denial of service vulnerability in Heimdal's PKI certificate validation library, affecting the KDC (via
    PKINIT) and kinit (via PKINIT), as well as any third-party applications using Heimdal's libhx509. Users
    should upgrade to Heimdal 7.7.1 or 7.8. There are no known workarounds for this issue. (CVE-2022-41916)

  - PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that
    may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit
    platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other
    platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has a similar bug.
    (CVE-2022-42898)

  - Heimdal before 7.7.1 allows remote attackers to execute arbitrary code because of an invalid free in the
    ASN.1 codec used by the Key Distribution Center (KDC). (CVE-2022-44640)

  - The fix for CVE-2022-3437 included changing memcmp to be constant time and a workaround for a compiler bug
    by adding != 0 comparisons to the result of memcmp. When these patches were backported to the
    heimdal-7.7.1 and heimdal-7.8.0 branches (and possibly other branches) a logic inversion sneaked in
    causing the validation of message integrity codes in gssapi/arcfour to be inverted. (CVE-2022-45142)

  -  Please review the referenced CVE identifiers for details.  (CVE-2022-44758)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202310-06");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=881429");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=893722");
  script_set_attribute(attribute:"solution", value:
"All Cross-realm trust vulnerability in Heimdal users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-crypt/heimdal-7.8.0-r1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14870");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-44640");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:heimdal");
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
    'name' : 'app-crypt/heimdal',
    'unaffected' : make_list("ge 7.8.0-r1"),
    'vulnerable' : make_list("lt 7.8.0-r1")
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
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Heimdal');
}
