#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202311-16.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(186285);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/26");

  script_cve_id(
    "CVE-2020-27827",
    "CVE-2020-35498",
    "CVE-2021-3905",
    "CVE-2021-36980",
    "CVE-2022-4337",
    "CVE-2022-4338",
    "CVE-2023-1668"
  );

  script_name(english:"GLSA-202311-16 : Open vSwitch: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202311-16 (Open vSwitch: Multiple Vulnerabilities)

  - A flaw was found in multiple versions of OpenvSwitch. Specially crafted LLDP packets can cause memory to
    be lost when allocating data to handle specific optional TLVs, potentially causing a denial of service.
    The highest threat from this vulnerability is to system availability. (CVE-2020-27827)

  - A vulnerability was found in openvswitch. A limitation in the implementation of userspace packet parsing
    can allow a malicious user to send a specially crafted packet causing the resulting megaflow in the kernel
    to be too wide, potentially causing a denial of service. The highest threat from this vulnerability is to
    system availability. (CVE-2020-35498)

  - A memory leak was found in Open vSwitch (OVS) during userspace IP fragmentation processing. An attacker
    could use this flaw to potentially exhaust available memory by keeping sending packet fragments.
    (CVE-2021-3905)

  - Open vSwitch (aka openvswitch) 2.11.0 through 2.15.0 has a use-after-free in decode_NXAST_RAW_ENCAP
    (called from ofpact_decode and ofpacts_decode) during the decoding of a RAW_ENCAP action. (CVE-2021-36980)

  - An out-of-bounds read in Organization Specific TLV was found in various versions of OpenvSwitch.
    (CVE-2022-4337)

  - An integer underflow in Organization Specific TLV was found in various versions of OpenvSwitch.
    (CVE-2022-4338)

  - A flaw was found in openvswitch (OVS). When processing an IP packet with protocol 0, OVS will install the
    datapath flow without the action modifying the IP header. This issue results (for both kernel and
    userspace datapath) in installing a datapath flow matching all IP protocols (nw_proto is wildcarded) for
    this flow, but with an incorrect action, possibly causing incorrect handling of other IP packets with a !=
    0 IP protocol that matches this dp flow. (CVE-2023-1668)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202311-16");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=765346");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=769995");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=803107");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=887561");
  script_set_attribute(attribute:"solution", value:
"All Open vSwitch users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-misc/openvswitch-2.17.6");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35498");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-4338");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openvswitch");
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
    'name' : 'net-misc/openvswitch',
    'unaffected' : make_list("ge 2.17.6"),
    'vulnerable' : make_list("lt 2.17.6")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Open vSwitch');
}
