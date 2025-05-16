#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202309-02.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(181506);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id(
    "CVE-2022-3725",
    "CVE-2023-0666",
    "CVE-2023-0667",
    "CVE-2023-0668",
    "CVE-2023-1161",
    "CVE-2023-1992",
    "CVE-2023-1993",
    "CVE-2023-1994",
    "CVE-2023-2854",
    "CVE-2023-2855",
    "CVE-2023-2856",
    "CVE-2023-2857",
    "CVE-2023-2858",
    "CVE-2023-2879",
    "CVE-2023-2952"
  );

  script_name(english:"GLSA-202309-02 : Wireshark: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202309-02 (Wireshark: Multiple Vulnerabilities)

  - Crash in the OPUS protocol dissector in Wireshark 3.6.0 to 3.6.8 allows denial of service via packet
    injection or crafted capture file (CVE-2022-3725)

  - Due to failure in validating the length provided by an attacker-crafted RTPS packet, Wireshark version
    4.0.5 and prior, by default, is susceptible to a heap-based buffer overflow, and possibly code execution
    in the context of the process running Wireshark. (CVE-2023-0666)

  - Due to failure in validating the length provided by an attacker-crafted MSMMS packet, Wireshark version
    4.0.5 and prior, in an unusual configuration, is susceptible to a heap-based buffer overflow, and possibly
    code execution in the context of the process running Wireshark (CVE-2023-0667)

  - Due to failure in validating the length provided by an attacker-crafted IEEE-C37.118 packet, Wireshark
    version 4.0.5 and prior, by default, is susceptible to a heap-based buffer overflow, and possibly code
    execution in the context of the process running Wireshark. (CVE-2023-0668)

  - ISO 15765 and ISO 10681 dissector crash in Wireshark 4.0.0 to 4.0.3 and 3.6.0 to 3.6.11 allows denial of
    service via packet injection or crafted capture file (CVE-2023-1161)

  - RPCoRDMA dissector crash in Wireshark 4.0.0 to 4.0.4 and 3.6.0 to 3.6.12 allows denial of service via
    packet injection or crafted capture file (CVE-2023-1992)

  - LISP dissector large loop in Wireshark 4.0.0 to 4.0.4 and 3.6.0 to 3.6.12 allows denial of service via
    packet injection or crafted capture file (CVE-2023-1993)

  - GQUIC dissector crash in Wireshark 4.0.0 to 4.0.4 and 3.6.0 to 3.6.12 allows denial of service via packet
    injection or crafted capture file (CVE-2023-1994)

  - BLF file parser crash in Wireshark 4.0.0 to 4.0.5 and 3.6.0 to 3.6.13 allows denial of service via crafted
    capture file (CVE-2023-2854, CVE-2023-2857)

  - Candump log parser crash in Wireshark 4.0.0 to 4.0.5 and 3.6.0 to 3.6.13 allows denial of service via
    crafted capture file (CVE-2023-2855)

  - VMS TCPIPtrace file parser crash in Wireshark 4.0.0 to 4.0.5 and 3.6.0 to 3.6.13 allows denial of service
    via crafted capture file (CVE-2023-2856)

  - NetScaler file parser crash in Wireshark 4.0.0 to 4.0.5 and 3.6.0 to 3.6.13 allows denial of service via
    crafted capture file (CVE-2023-2858)

  - GDSDB infinite loop in Wireshark 4.0.0 to 4.0.5 and 3.6.0 to 3.6.13 allows denial of service via packet
    injection or crafted capture file (CVE-2023-2879)

  - XRA dissector infinite loop in Wireshark 4.0.0 to 4.0.5 and 3.6.0 to 3.6.13 allows denial of service via
    packet injection or crafted capture file (CVE-2023-2952)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202309-02");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=878421");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=899548");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=904248");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=907133");
  script_set_attribute(attribute:"solution", value:
"All Wireshark users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-analyzer/wireshark-4.0.6");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1161");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wireshark");
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
    'name' : 'net-analyzer/wireshark',
    'unaffected' : make_list("ge 4.0.6"),
    'vulnerable' : make_list("lt 4.0.6")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Wireshark');
}
