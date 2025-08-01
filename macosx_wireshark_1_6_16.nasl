#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176418);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/14");

  script_cve_id("CVE-2013-4074", "CVE-2013-4081", "CVE-2013-4083");
  script_xref(name:"IAVB", value:"2013-B-0067-S");

  script_name(english:"Wireshark 1.6.x < 1.6.16 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS / Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote macOS / Mac OS X host is prior to 1.6.16. It is, therefore, affected by
multiple vulnerabilities as referenced in the wireshark-1.6.16 advisory.

  - The dissect_capwap_data function in epan/dissectors/packet-capwap.c in the CAPWAP dissector in Wireshark
    1.6.x before 1.6.16 and 1.8.x before 1.8.8 incorrectly uses a -1 data value to represent an error
    condition, which allows remote attackers to cause a denial of service (application crash) via a crafted
    packet. (CVE-2013-4074)

  - The http_payload_subdissector function in epan/dissectors/packet-http.c in the HTTP dissector in Wireshark
    1.6.x before 1.6.16 and 1.8.x before 1.8.8 does not properly determine when to use a recursive approach,
    which allows remote attackers to cause a denial of service (stack consumption) via a crafted packet.
    (CVE-2013-4081)

  - The dissect_pft function in epan/dissectors/packet-dcp-etsi.c in the DCP ETSI dissector in Wireshark 1.6.x
    before 1.6.16, 1.8.x before 1.8.8, and 1.10.0 does not validate a certain fragment length value, which
    allows remote attackers to cause a denial of service (application crash) via a crafted packet.
    (CVE-2013-4083)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.6.16.html");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8725");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-32");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8733");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-39");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8717");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-41");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.6.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4083");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-4081");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Wireshark');

var constraints = [
  { 'min_version' : '1.6.0', 'max_version' : '1.6.15', 'fixed_version' : '1.6.16' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
