#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180101);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/23");

  script_cve_id(
    "CVE-2013-3562",
    "CVE-2017-9346",
    "CVE-2017-9766",
    "CVE-2018-9262",
    "CVE-2021-39929",
    "CVE-2023-2906",
    "CVE-2023-4511",
    "CVE-2023-4512",
    "CVE-2023-4513"
  );
  script_xref(name:"IAVB", value:"2017-B-0067-S");
  script_xref(name:"IAVB", value:"2021-B-0065-S");
  script_xref(name:"IAVB", value:"2023-B-0063-S");

  script_name(english:"Wireshark 4.0.x < 4.0.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is prior to 4.0.8. It is, therefore, affected by multiple
vulnerabilities as referenced in the wireshark-4.0.8 advisory.

  - Multiple integer signedness errors in the tvb_unmasked function in epan/dissectors/packet-websocket.c in
    the Websocket dissector in Wireshark 1.8.x before 1.8.7 allow remote attackers to cause a denial of
    service (application crash) via a malformed packet. (CVE-2013-3562)

  - In Wireshark 2.2.0 to 2.2.6 and 2.0.0 to 2.0.12, the SoulSeek dissector could go into an infinite loop.
    This was addressed in epan/dissectors/packet-slsk.c by making loop bounds more explicit. (CVE-2017-9346)

  - In Wireshark 2.2.7, PROFINET IO data with a high recursion depth allows remote attackers to cause a denial
    of service (stack exhaustion) in the dissect_IODWriteReq function in plugins/profinet/packet-dcerpc-pn-
    io.c. (CVE-2017-9766)

  - In Wireshark 2.4.0 to 2.4.5 and 2.2.0 to 2.2.13, the VLAN dissector could crash. This was addressed in
    epan/dissectors/packet-vlan.c by limiting VLAN tag nesting to restrict the recursion depth.
    (CVE-2018-9262)

  - Uncontrolled Recursion in the Bluetooth DHT dissector in Wireshark 3.4.0 to 3.4.9 and 3.2.0 to 3.2.17
    allows denial of service via packet injection or crafted capture file (CVE-2021-39929)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-4.0.8.html");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/19144");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-23");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/19258");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-24");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/19259");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-25");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/19229");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-26");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 4.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9346");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-4513");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '4.0.0', 'max_version' : '4.0.7', 'fixed_version' : '4.0.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
