#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164596);
  script_version("1.110");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2015-2716",
    "CVE-2015-9289",
    "CVE-2017-1000476",
    "CVE-2017-11166",
    "CVE-2017-12805",
    "CVE-2017-12806",
    "CVE-2017-15710",
    "CVE-2017-17807",
    "CVE-2017-18251",
    "CVE-2017-18252",
    "CVE-2017-18254",
    "CVE-2017-18271",
    "CVE-2017-18273",
    "CVE-2017-18595",
    "CVE-2017-6519",
    "CVE-2018-10177",
    "CVE-2018-10360",
    "CVE-2018-10804",
    "CVE-2018-10805",
    "CVE-2018-1116",
    "CVE-2018-11656",
    "CVE-2018-12599",
    "CVE-2018-12600",
    "CVE-2018-1301",
    "CVE-2018-13153",
    "CVE-2018-14434",
    "CVE-2018-14435",
    "CVE-2018-14436",
    "CVE-2018-14437",
    "CVE-2018-15587",
    "CVE-2018-15607",
    "CVE-2018-16328",
    "CVE-2018-16749",
    "CVE-2018-16750",
    "CVE-2018-17199",
    "CVE-2018-18066",
    "CVE-2018-18544",
    "CVE-2018-19985",
    "CVE-2018-20169",
    "CVE-2018-20467",
    "CVE-2018-20852",
    "CVE-2018-4180",
    "CVE-2018-4181",
    "CVE-2018-4700",
    "CVE-2018-5745",
    "CVE-2018-7191",
    "CVE-2018-8804",
    "CVE-2018-9133",
    "CVE-2019-10131",
    "CVE-2019-10207",
    "CVE-2019-10638",
    "CVE-2019-10639",
    "CVE-2019-10650",
    "CVE-2019-11190",
    "CVE-2019-11470",
    "CVE-2019-11472",
    "CVE-2019-11597",
    "CVE-2019-11598",
    "CVE-2019-11884",
    "CVE-2019-12382",
    "CVE-2019-12974",
    "CVE-2019-12975",
    "CVE-2019-12976",
    "CVE-2019-12978",
    "CVE-2019-12979",
    "CVE-2019-13133",
    "CVE-2019-13134",
    "CVE-2019-13135",
    "CVE-2019-13232",
    "CVE-2019-13233",
    "CVE-2019-13295",
    "CVE-2019-13297",
    "CVE-2019-13300",
    "CVE-2019-13301",
    "CVE-2019-13304",
    "CVE-2019-13305",
    "CVE-2019-13306",
    "CVE-2019-13307",
    "CVE-2019-13309",
    "CVE-2019-13310",
    "CVE-2019-13311",
    "CVE-2019-13454",
    "CVE-2019-13648",
    "CVE-2019-14283",
    "CVE-2019-14815",
    "CVE-2019-14980",
    "CVE-2019-14981",
    "CVE-2019-15090",
    "CVE-2019-15139",
    "CVE-2019-15140",
    "CVE-2019-15141",
    "CVE-2019-15221",
    "CVE-2019-15916",
    "CVE-2019-16056",
    "CVE-2019-16708",
    "CVE-2019-16709",
    "CVE-2019-16710",
    "CVE-2019-16711",
    "CVE-2019-16712",
    "CVE-2019-16713",
    "CVE-2019-16746",
    "CVE-2019-17041",
    "CVE-2019-17042",
    "CVE-2019-17540",
    "CVE-2019-17541",
    "CVE-2019-18660",
    "CVE-2019-19527",
    "CVE-2019-19768",
    "CVE-2019-19948",
    "CVE-2019-19949",
    "CVE-2019-2737",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2805",
    "CVE-2019-3820",
    "CVE-2019-3890",
    "CVE-2019-3901",
    "CVE-2019-5436",
    "CVE-2019-6465",
    "CVE-2019-6477",
    "CVE-2019-7175",
    "CVE-2019-7397",
    "CVE-2019-7398",
    "CVE-2019-9503",
    "CVE-2019-9924",
    "CVE-2019-9956",
    "CVE-2020-10711",
    "CVE-2020-10757",
    "CVE-2020-11868",
    "CVE-2020-12049",
    "CVE-2020-12653",
    "CVE-2020-12654",
    "CVE-2020-12888",
    "CVE-2020-13817",
    "CVE-2020-14556",
    "CVE-2020-14577",
    "CVE-2020-14578",
    "CVE-2020-14579",
    "CVE-2020-14583",
    "CVE-2020-14593",
    "CVE-2020-14621",
    "CVE-2020-2754",
    "CVE-2020-2755",
    "CVE-2020-2756",
    "CVE-2020-2757",
    "CVE-2020-2767",
    "CVE-2020-2773",
    "CVE-2020-2778",
    "CVE-2020-2781",
    "CVE-2020-2800",
    "CVE-2020-2803",
    "CVE-2020-2805",
    "CVE-2020-2816",
    "CVE-2020-2830",
    "CVE-2020-5208",
    "CVE-2020-8616",
    "CVE-2020-8617"
  );

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.15.3)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.15.3. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.15.3 advisory.

  - In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer overflow in the function WriteSGIImage of
    coders/sgi.c. (CVE-2019-19948)

  - The Broadcom brcmfmac WiFi driver prior to commit a4176ec356c73a46c07c181c6d04039fafa34a9f is vulnerable
    to a frame validation bypass. If the brcmfmac driver receives a firmware event frame from a remote source,
    the is_wlc_event_frame function will cause this frame to be discarded and unprocessed. If the driver
    receives the firmware event frame from the host, the appropriate handler is called. This frame validation
    can be bypassed if the bus used is USB (for instance by a wifi dongle). This can allow firmware event
    frames from a remote source to be processed. In the worst case scenario, by sending specially-crafted WiFi
    packets, a remote, unauthenticated attacker may be able to execute arbitrary code on a vulnerable system.
    More typically, this vulnerability will result in denial-of-service conditions. (CVE-2019-9503)

  - An issue was discovered in Rsyslog v8.1908.0. contrib/pmaixforwardedfrom/pmaixforwardedfrom.c has a heap
    overflow in the parser for AIX log messages. The parser tries to locate a log message delimiter (in this
    case, a space or a colon) but fails to account for strings that do not satisfy this constraint. If the
    string does not match, then the variable lenMsg will reach the value zero and will skip the sanity check
    that detects invalid log messages. The message will then be considered valid, and the parser will eat up
    the nonexistent colon delimiter. In doing so, it will decrement lenMsg, a signed integer, whose value was
    zero and now becomes minus one. The following step in the parser is to shift left the contents of the
    message. To do this, it will call memmove with the right pointers to the target and destination strings,
    but the lenMsg will now be interpreted as a huge value, causing a heap overflow. (CVE-2019-17041)

  - An issue was discovered in Rsyslog v8.1908.0. contrib/pmcisconames/pmcisconames.c has a heap overflow in
    the parser for Cisco log messages. The parser tries to locate a log message delimiter (in this case, a
    space or a colon), but fails to account for strings that do not satisfy this constraint. If the string
    does not match, then the variable lenMsg will reach the value zero and will skip the sanity check that
    detects invalid log messages. The message will then be considered valid, and the parser will eat up the
    nonexistent colon delimiter. In doing so, it will decrement lenMsg, a signed integer, whose value was zero
    and now becomes minus one. The following step in the parser is to shift left the contents of the message.
    To do this, it will call memmove with the right pointers to the target and destination strings, but the
    lenMsg will now be interpreted as a huge value, causing a heap overflow. (CVE-2019-17042)

  - An issue was discovered in dbus >= 1.3.0 before 1.12.18. The DBusServer in libdbus, as used in dbus-
    daemon, leaks file descriptors when a message exceeds the per-message file descriptor limit. A local
    attacker with access to the D-Bus system bus or another system service's private AF_UNIX socket could use
    this to make the system service reach its file descriptor limit, denying service to subsequent D-Bus
    clients. (CVE-2020-12049)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.15.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6382cc23");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9503");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19948");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2019-17042");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '5.15.3', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.15.3 or higher.', 'lts' : TRUE },
  { 'fixed_version' : '5.15.3', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.15.3 or higher.', 'lts' : TRUE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
