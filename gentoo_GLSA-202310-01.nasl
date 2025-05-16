#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202310-01.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(182411);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/01");

  script_cve_id(
    "CVE-2022-20698",
    "CVE-2022-20770",
    "CVE-2022-20771",
    "CVE-2022-20785",
    "CVE-2022-20792",
    "CVE-2022-20796",
    "CVE-2022-20803",
    "CVE-2023-20032",
    "CVE-2023-20052"
  );

  script_name(english:"GLSA-202310-01 : ClamAV: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202310-01 (ClamAV: Multiple Vulnerabilities)

  - A vulnerability in the OOXML parsing module in Clam AntiVirus (ClamAV) Software version 0.104.1 and LTS
    version 0.103.4 and prior versions could allow an unauthenticated, remote attacker to cause a denial of
    service condition on an affected device. The vulnerability is due to improper checks that may result in an
    invalid pointer read. An attacker could exploit this vulnerability by sending a crafted OOXML file to an
    affected device. An exploit could allow the attacker to cause the ClamAV scanning process to crash,
    resulting in a denial of service condition. (CVE-2022-20698)

  - On April 20, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in CHM file parser of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an
    unauthenticated, remote attacker to cause a denial of service condition on an affected device. For a
    description of this vulnerability, see the ClamAV blog. This advisory will be updated as additional
    information becomes available. (CVE-2022-20770)

  - On April 20, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in the TIFF file parser of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an
    unauthenticated, remote attacker to cause a denial of service condition on an affected device. For a
    description of this vulnerability, see the ClamAV blog. This advisory will be updated as additional
    information becomes available. (CVE-2022-20771)

  - On April 20, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in HTML file parser of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an
    unauthenticated, remote attacker to cause a denial of service condition on an affected device. For a
    description of this vulnerability, see the ClamAV blog. This advisory will be updated as additional
    information becomes available. (CVE-2022-20785)

  - A vulnerability in the regex module used by the signature database load module of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an authenticated,
    local attacker to crash ClamAV at database load time, and possibly gain code execution. The vulnerability
    is due to improper bounds checking that may result in a multi-byte heap buffer overwflow write. An
    attacker could exploit this vulnerability by placing a crafted CDB ClamAV signature database file in the
    ClamAV database directory. An exploit could allow the attacker to run code as the clamav user.
    (CVE-2022-20792)

  - On May 4, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in Clam AntiVirus (ClamAV) versions 0.103.4,
    0.103.5, 0.104.1, and 0.104.2 could allow an authenticated, local attacker to cause a denial of service
    condition on an affected device. For a description of this vulnerability, see the ClamAV blog.
    (CVE-2022-20796)

  - A vulnerability in the OLE2 file parser of Clam AntiVirus (ClamAV) versions 0.104.0 through 0.104.2 could
    allow an unauthenticated, remote attacker to cause a denial of service condition on an affected device.The
    vulnerability is due to incorrect use of the realloc function that may result in a double-free. An
    attacker could exploit this vulnerability by submitting a crafted OLE2 file to be scanned by ClamAV on the
    affected device. An exploit could allow the attacker to cause the ClamAV scanning process to crash,
    resulting in a denial of service condition. (CVE-2022-20803)

  - On Feb 15, 2023, the following vulnerability in the ClamAV scanning library was disclosed: A vulnerability
    in the HFS+ partition file parser of ClamAV versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7
    and earlier could allow an unauthenticated, remote attacker to execute arbitrary code. This vulnerability
    is due to a missing buffer size check that may result in a heap buffer overflow write. An attacker could
    exploit this vulnerability by submitting a crafted HFS+ partition file to be scanned by ClamAV on an
    affected device. A successful exploit could allow the attacker to execute arbitrary code with the
    privileges of the ClamAV scanning process, or else crash the process, resulting in a denial of service
    (DoS) condition. For a description of this vulnerability, see the ClamAV blog
    [https://blog.clamav.net/]. (CVE-2023-20032)

  - On Feb 15, 2023, the following vulnerability in the ClamAV scanning library was disclosed: A vulnerability
    in the DMG file parser of ClamAV versions 1.0.0 and earlier, 0.105.1 and earlier, and 0.103.7 and earlier
    could allow an unauthenticated, remote attacker to access sensitive information on an affected device.
    This vulnerability is due to enabling XML entity substitution that may result in XML external entity
    injection. An attacker could exploit this vulnerability by submitting a crafted DMG file to be scanned by
    ClamAV on an affected device. A successful exploit could allow the attacker to leak bytes from any file
    that may be read by the ClamAV scanning process. (CVE-2023-20052)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202310-01");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831083");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=842813");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=894672");
  script_set_attribute(attribute:"solution", value:
"All ClamAV users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-antivirus/clamav-0.103.7");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20785");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-20032");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:clamav");
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
    'name' : 'app-antivirus/clamav',
    'unaffected' : make_list("ge 0.103.7"),
    'vulnerable' : make_list("lt 0.103.7")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ClamAV');
}
