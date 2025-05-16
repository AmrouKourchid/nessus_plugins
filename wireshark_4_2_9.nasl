#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211657);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2024-11595", "CVE-2024-11596");
  script_xref(name:"IAVB", value:"2024-B-0185-S");

  script_name(english:"Wireshark 4.2.x < 4.2.9 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is prior to 4.2.9. It is, therefore, affected by multiple
vulnerabilities as referenced in the wireshark-4.2.9 advisory.

  - The FiveCo RAP dissector could go into an infinite loop. Fixed in master: d8ca9fc339 Fixed in release-4.4:
    4d58fef602 Fixed in release-4.2: 686dff0f01 Discovered in our internal testing environment. We are unaware
    of any exploits for this issue. It may be possible to make Wireshark consume excessive CPU resources by
    injecting a malformed packet onto the wire or by convincing someone to read a malformed packet trace file.
    (CVE-2024-11595)

  - The ECMP dissector could crash. Fixed in master: c8e5887073 Fixed in release-4.4: 8fd60c6448 Fixed in
    release-4.2: 06e0b0bb09 Discovered by Ivan Nardi We are unaware of any exploits for this issue. It may be
    possible to make Wireshark crash by injecting a malformed packet onto the wire or by convincing someone to
    read a malformed packet trace file. (CVE-2024-11596)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-4.2.9.html");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/20176");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2024-14");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/20214");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2024-15");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 4.2.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11596");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '4.2.0', 'max_version' : '4.2.8', 'fixed_version' : '4.2.9' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
