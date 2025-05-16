#TRUSTED 51db02cc1ae998f653e8dca52bf29e516b4b39cf30aa414574b04aed7d852c0a7c0b94b4f5a7c4318b76ab504fd99cfa7a9df959dd24111067fe62b64b4c974bba6ba477f891e4d803a1bf4a3a2e970d580bd72f5b7b266fe71ceaaf18e4b70d4070904c317d18d03c3a80dcb775b2274e226424ed2e1b95b45766da2a1a190b37b02568bcb56d0b6b4ef1a3386535b51159059deda923338223ed4b0a39252f4ee82a46085f7942d78940fc731db5861d124d9330c71b3547f6dd87412f319e3d3a3e9b81bb421bfc623c0e8f181463846da587b392703f289fc5f67683fc426580eb25158b8fe802947835d6f5fd339d9bd68a6d090ecd6c659779f75e58c2fea6dffe7eaae112299f7921d348fb309488e48179c5e49da062adde814f37bc0ecac13553277de7920938aef869caf7170309d4e4f302f7b8c8cb45877b7028ee60c11f40590e44c73aead3f21a4767c2d5fb5006f7b65baec7af8627951456ef8218603346750aaea5b84c101dd9011f74450e8bb18e4433bf371dba18a22fdc91bb62d4d8e6f9dc12122e605cd00925e5ce248e7e7242e9f30c6260ee38224021d04684a97340f913ac701aa050be539718da77118c65b56dfae5cb71a0f03da212fddf32727bcffe0dae4f9efd571acc3d17fc4a3c67d76c4550f1c9795da8743ba349795f0ef163eae962de6cdd5b0ee3245391e2ef7d53f388ce389f6f
#TRUST-RSA-SHA256 9d3e681e3d62df259de986cd18e77e3fbc500fbcb4fcb4159ba4541be52f01f52e4959421ba1490b55468e21085b7ed28e78311001faf8dc08c87bb986fff7da4d2f21a2ea2e584f1beb8dfd9d962f4a1fede608f78760d08fccc6f6aad039d0fb200e07ba2a2c41d67a243473a87d3a9920dd233e2fe1559c0354e797a62e651aa8dcd2130e4a475be8486cf91f21866e786a9b5633314f42ed7999977b3fe3bb072dfe0cbdbd0d3f3eaaf50656237a3e4c57ab2eca019a5b18f42bcb6505a93b77cdf10c27ca777e6ad488d44e27c00d85b4849c2125f86f9d06522ff00758cb7e5fc72210f83ab5c33c8a331c640ad9bb41cb575400c321647ac2cbb5bf6573ac161b06639f16ed1f69cfafc6cb4cd3e86b703b7d7295b6c11790baa0b2bae1632ec9c73a6417ce724e223dd0ba7dc1844f7e4fd35aa5a620d7436ab73c1f8c857fc26eae24ab0f41394ff1ab9c44cd849b505dbe9f6e4be65f6b93deb331eb77e63b8f826f05c8cdab04d652c4505d02b724dd71cf2d73fbcd131126fd1b803c0f2473a7031c6f9161a84c07a20adf2e756219b6052ed6a967c25dbfe59414da06cff3d78a31f4bf0f717015725de5fca0a909a3fdc42720b838200ac001b1148d168662fc12fd6c983f30f15a4a2c3633f0a92b94fd788463031540ee7638b904710f3f0104737b302dad4c9d5da2e5c92878c2f659fdd958590e99e010
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165215);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2022-20849");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa57311");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-bng-Gmg5Gxt");
  script_xref(name:"IAVA", value:"2022-A-0380-S");

  script_name(english:"Cisco IOS XR Software Broadband Network Gateway PPP over Ethernet DoS (cisco-sa-iosxr-bng-Gmg5Gxt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in IOS XR Software due to the PPPoE feature not properly handling an
error condition within a specific crafted packet sequence. An unauthenticated, adjacent  attacker can exploit this
issue, via a sequence of specific PPPoE packets from controlled customer premises equipment (CPE), to cause the
process to continuously restart.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-bng-Gmg5Gxt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e145bee");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74840");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa57311");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa57311");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20849");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(391);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');
var smus = {};

var model = toupper(product_info.model);

if ('ASR9K' >< model)
{
    smus['6.7.3'] = 'CSCwa57311';
    smus['7.3.2'] = 'CSCwa57311';
    smus['7.4.2'] = 'CSCwa57311';
}

var vuln_ranges = [
 {'min_ver': '0.0', 'fix_ver': '7.5.2'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
var workaround_params = {'pat' : "pppoe padr session-unique relay-session-id($|\r\n)"};

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa57311'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  smus:smus,
  vuln_ranges:vuln_ranges
);
