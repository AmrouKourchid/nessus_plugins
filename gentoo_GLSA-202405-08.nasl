#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202405-08.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(194978);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/04");

  script_cve_id(
    "CVE-2021-41991",
    "CVE-2021-45079",
    "CVE-2022-40617",
    "CVE-2023-26463"
  );

  script_name(english:"GLSA-202405-08 : strongSwan: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202405-08 (strongSwan: Multiple Vulnerabilities)

  - The in-memory certificate cache in strongSwan before 5.9.4 has a remote integer overflow upon receiving
    many requests with different certificates to fill the cache and later trigger the replacement of cache
    entries. The code attempts to select a less-often-used cache entry by means of a random number generator,
    but this is not done correctly. Remote code execution might be a slight possibility. (CVE-2021-41991)

  - In strongSwan before 5.9.5, a malicious responder can send an EAP-Success message too early without
    actually authenticating the client and (in the case of EAP methods with mutual authentication and EAP-only
    authentication for IKEv2) even without server authentication. (CVE-2021-45079)

  - strongSwan before 5.9.8 allows remote attackers to cause a denial of service in the revocation plugin by
    sending a crafted end-entity (and intermediate CA) certificate that contains a CRL/OCSP URL that points to
    a server (under the attacker's control) that doesn't properly respond but (for example) just does nothing
    after the initial TCP handshake, or sends an excessive amount of application data. (CVE-2022-40617)

  - strongSwan 5.9.8 and 5.9.9 potentially allows remote code execution because it uses a variable named
    public for two different purposes within the same function. There is initially incorrect access control,
    later followed by an expired pointer dereference. One attack vector is sending an untrusted client
    certificate during EAP-TLS. A server is affected only if it loads plugins that implement TLS-based EAP
    methods (EAP-TLS, EAP-TTLS, EAP-PEAP, or EAP-TNC). This is fixed in 5.9.10. (CVE-2023-26463)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202405-08");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=818841");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=832460");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=878887");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=899964");
  script_set_attribute(attribute:"solution", value:
"All strongSwan users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-vpn/strongswan-5.9.10");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45079");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-26463");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:strongswan");
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
    'name' : 'net-vpn/strongswan',
    'unaffected' : make_list("ge 5.9.10"),
    'vulnerable' : make_list("lt 5.9.10")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'strongSwan');
}
