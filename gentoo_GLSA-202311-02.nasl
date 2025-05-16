#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202311-02.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(184175);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/01");

  script_cve_id(
    "CVE-2021-31439",
    "CVE-2022-0194",
    "CVE-2022-22995",
    "CVE-2022-23121",
    "CVE-2022-23122",
    "CVE-2022-23123",
    "CVE-2022-23124",
    "CVE-2022-23125",
    "CVE-2022-45188"
  );

  script_name(english:"GLSA-202311-02 : Netatalk: Multiple Vulnerabilities including root remote code execution");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202311-02 (Netatalk: Multiple Vulnerabilities
including root remote code execution)

  - This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations
    of Synology DiskStation Manager. Authentication is not required to exploit this vulnerablity. The specific
    flaw exists within the processing of DSI structures in Netatalk. The issue results from the lack of proper
    validation of the length of user-supplied data prior to copying it to a heap-based buffer. An attacker can
    leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-12326.
    (CVE-2021-31439)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the ad_addcomment function. The issue results from the lack of proper validation of the length of user-
    supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this
    vulnerability to execute code in the context of root. Was ZDI-CAN-15876. (CVE-2022-0194)

  - The combination of primitives offered by SMB and AFP in their default configuration allows the arbitrary
    writing of files. By exploiting these combination of primitives, an attacker can execute arbitrary code.
    (CVE-2022-22995)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the parse_entries function. The issue results from the lack of proper error handling when parsing
    AppleDouble entries. An attacker can leverage this vulnerability to execute code in the context of root.
    Was ZDI-CAN-15819. (CVE-2022-23121)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the setfilparams function. The issue results from the lack of proper validation of the length of user-
    supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this
    vulnerability to execute code in the context of root. Was ZDI-CAN-15837. (CVE-2022-23122)

  - This vulnerability allows remote attackers to disclose sensitive information on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the getdirparams method. The issue results from the lack of proper validation of user-supplied data, which
    can result in a read past the end of an allocated buffer. An attacker can leverage this in conjunction
    with other vulnerabilities to execute arbitrary code in the context of root. Was ZDI-CAN-15830.
    (CVE-2022-23123)

  - This vulnerability allows remote attackers to disclose sensitive information on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the get_finderinfo method. The issue results from the lack of proper validation of user-supplied data,
    which can result in a read past the end of an allocated buffer. An attacker can leverage this in
    conjunction with other vulnerabilities to execute arbitrary code in the context of root. Was ZDI-
    CAN-15870. (CVE-2022-23124)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the copyapplfile function. When parsing the len element, the process does not properly validate the length
    of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage
    this vulnerability to execute code in the context of root. Was ZDI-CAN-15869. (CVE-2022-23125)

  - Netatalk through 3.1.13 has an afp_getappl heap-based buffer overflow resulting in code execution via a
    crafted .appl file. This provides remote root access on some platforms such as FreeBSD (used for TrueNAS).
    (CVE-2022-45188)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202311-02");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=837623");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=881259");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=915354");
  script_set_attribute(attribute:"solution", value:
"All Netatalk users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-fs/netatalk-3.1.18");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22995");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23125");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:netatalk");
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
    'name' : 'net-fs/netatalk',
    'unaffected' : make_list("ge 3.1.18"),
    'vulnerable' : make_list("lt 3.1.18")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Netatalk');
}
