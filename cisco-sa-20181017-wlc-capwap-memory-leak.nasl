#TRUSTED 2b5d96b03cd430c449501c6085501222aff6f87776707a4cc8f53f8abcb0074245eff0bf71da4730dba2c1b752f8ab256964a8df1eca93bad9830efe4cf71a6f06bc40d9872deb709a557654aaf41820c593426fac3ee235cbaba65d42eb39cfd79c61c89c9d65fa79de573a6735e59433a84b9ec5def9a27b7285c0385227f184f643127575e0f02c83b0fca007fea06bfdbba14928835a989fd18990335fcb6c19d2b8de8ab3c4e8e203b43a92e2550848c6aab2515db39fc6d0e0cd1b3f8b01b5da321c34a758fbe3a88d1e0467a7f6544528ee1fadd536ed5be2e69b1f0471c717e7f6b386fe42d6f671611a50d1d30e8ff09f85aa20522db7b72016c775b7e7c5ed22053b9aef0b167d09b16e86d5758a067dd276a10de64f831011103d04dc19583d7a596a5953ff37fbcc98040bb69222f50958a6cbbdc2f959c7c2eccd4f83055c547a09ff885d605a53db404a8eae79ef5fdfe6b817e9a587016f0edc30cef4300dc40214e0e49e819e34a90e7db0e5a1006eb9663ad93509fc95cb01e0433f11ae81ae7427e1a4abcf75f8ef23734bbadb55693a8614e0545adaf74ae99585a241554beabb528d5b87029cca0f5c82e78503cbd48d4afbf41b2137504ecb9ce8bde8a49edff3a18d3b2bd3221039e9ba8039d83f4797cdd89ae4a78a74dcb93c8d3f7731ea7f871e240ee7acc6f742b14af85e49c1304d853082a1
#TRUST-RSA-SHA256 7d7246b88cfa63f1e9ca123a62a94eac64d961dabc0cc7b79081a0c1eeebcd3ccf8978aae1ee3fbea0072c180b79ad8d3e6e54428ffcdeb23db17de4146b9e5e18102e553eff6be3363a444e1252b8d547d34ea2882cfd09599b0228c69521c019532ea3eabd690ca52682115ef91afb291fde76d915aec471f52da697b99aa129847556a66197d671b90a2923f836493c4101af8d1e39201f312b4288db10f4e6d6b52e396bb1322252740a778c05c0d56262055d1b1d29881991f39d665fbd596dd0f4ff56fb119aa766f2ac3e8f94e20de231cc9c95927db26fb71079d739852c7f88f9d5915cf7256af5890cf929b7ed78f4b43a4dc52c72b0546135b0a724c56d9495175202cc619466346369427587e4ae69eeafc2a7b07ccb4703d655708589dae793385b658143a2ca2904d319cdd1cde4899c2a8ea5a571d32523fc3a3b72f440e12d4fe75aa494193903b17c775695591a545b194d6dab5891f5d51467f1f38aa921fc49349bb2b5e1b6f8a92bd863b92393a77b6223ffa6387d3ae41c99a181d6589483f0ca4db678657386dd8b63fcfd1405debb7f8c146d43ad04e1c7cd1c49d16d1192c2f0866ab7571fa5cfae785adce63485abf3bc0b98540da925919451e1a1f43f6ce7f73b6082d946feea80ef354bb6809ff8dba82807d7073a683796d7801f8fc9b20376e17207d2f4273f58bba4d6da39af379e0928
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118461);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id(
    "CVE-2018-0417",
    "CVE-2018-0441",
    "CVE-2018-0442",
    "CVE-2018-0443"
  );
  script_bugtraq_id(
    105664,
    105667,
    105680,
    105686
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf66680");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh65876");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve64652");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf66696");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-wlc-capwap-memory-leak");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-wlc-gui-privesc");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-ap-ft-dos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-wlc-capwap-dos");

  script_name(english:"Cisco Wireless LAN Controller Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Wireless LAN
Controller (WLC) is affected by the following vulnerabilities:

  - A privilege escalation vulnerability due to improper parsing
    of a specific TACACS attribute. A remote attacker,
    authenticating to TACACs via the GUI, could create a local
    account with administrative privileges. (CVE-2018-0417)

  - A denial of service vulnerability due to flaws with specific
    timer mechanisms. A remote attacker could potentially cause
    the timer to crash resulting in a DoS condition.
    (CVE-2018-0441)

  - An information disclosure vulnerability due to insufficient
    checks when handling Control and Provisioning of Wireless
    Access Point keepalive requests. A remote attacker, with a
    specially crafted CAPWAP keepalive packet, could potentially
    read the devices memory. (CVE-2018-0442)

  - A denial of service vulnerability due to improper validation
    of CAPWAP discovery request packets. A remote attacker could
    potentially disconnect associated APs, resulting in a DoS
    condition. (CVE-2018-0443)

Please see the included Cisco BIDs and the Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-wlc-capwap-memory-leak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e14b610");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-wlc-capwap-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d106cd6");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-wlc-gui-privesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4eb02b4");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-ap-ft-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9605ddd");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf66680");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf66696");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh65876");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve64652");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvf66680, CSCvh65876, CSCve64652, and CSCvf66696.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0442");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-0417");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include("cisco_workarounds.inc");
include("ccf.inc");

var product_info = cisco::get_product_info(name:"Cisco Wireless LAN Controller (WLC)");

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '8.3.140.0' },
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.131.0' },
  { 'min_ver' : '8.6', 'fix_ver' : '8.7.102.0' }
];

var workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
var workaround_params = make_list();

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvf66680, CSCvh65876, CSCve64652, and CSCvf66696"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
