#TRUSTED 1a3b576c51eb3135441d6cee26f8591bb182212d8067990f0eb63ef51d872c311c5d295fe4f472c47dbb748f54581f890d33f89c0e1608c724de07629d5cbfd306eaf4f4f1803e6c2596246e17b11909566959f6b18607c7e0b2c0074ed4944f337781d1a4612e0670db05484bd8b2d410bde020b0f5c2f6d93f18cdfce9ef6663271ea6f55e3226a159175db33caad3ae7be1047783e70030a317efb870e3010b15e9ff83c6409cf137af19d16f60db8e22bbadd63bb59fc6bda8082ac343974f5f20fed4631f44fcde08df9aaeb9c936b98d7649d9f7fa4a830ad31451c83cff074641f2bd4a2328d9c8552c89f0e192c29dc82bc8c44e7e9e4cac2041ef9c8b4686f64c76e8711deb0753c55124be773b1e8ba86662811ab9acf735a2e15e3bc6c7fa5684f85eff9eaaccdb47b4db5d82a17833fd6fb351899875a157f5c658574da8a4d9e9ef66be247ad9e91a94ddff8b71b5c8d24bee533b3811f65170afe4d906914a335b9013462a75bff1897892a8b878f52fd09c0aa7e7867aaa3e504acb909cdadd2cf760e231108d9cc981c1df671bfa5e0f411e9682b7b06165ae0fa8240c523fc43d24bfdb2bffb5896f3c84ebf8df6219d9074749826b760cd198ae04a073a5990bfc73b96501f1da18880547c147eeaa528739b453c88bc0a93eaa72e33fe93c1ed195f97dc8609205445812dc24f0e5bef5958c4b0a7e94
#TRUST-RSA-SHA256 5acfd162a0424f2c8274f329cb32f247dbc54a6930941ec7183a2c78e875f212b5a69a86f32841b22d8ddc4fc314da230835906bd9fcdee39381b47e30deecca83c1f62f0e1bdd84bd8bea3c086ce0f6608b23c4fec1782e8cfcecfab9116f15365b723f14b70a12d0b13c59d4be08a608d3e8b2c76533220d0777a206636a9a3234d8ff077d127d87b1f64df675b0e65deb16c2eceae0bef919478d314006b4a105b08cdff9cefef35bd812ab6668460228ec9c5cc48534a59ce21b2a4fa0f1b678714581bfe4df0f00dd91f93ccf721ecf4947a8dea9f0ce9c2f6d72f42510aabef72178d6bf2c2859a3b093d07e3c6fb30e47a4f147ef80be2c85b17b64ce05a531475a9a54dfc3640a888df9d4924154849d81c89dffe349179544cb42e51ea28b5a631b0f429ff40d4ff5f723f798816aaf28df2fecfd64b9636c0ac5d169a311f78e9d9c12da5e7870e545805f164f584cb5b2d3249ce843c9a1f126465f2ea37c684e438f00283728608040b301f6649c133729c73d3e40a015759e39f163a1f5d3589c773d1fca0a3af7de4ad3a05eb45083e03b6d13c1df8c5eb876a765dfac4a134600f6da8b34b1fa4061e142b62a5bc0f7c5875b9f1205f67dd7497a7e54da2fb1f232954c63840d3d1e88cf161f711e0ba1c012fd636bd2ee30218104738ab336a76525ad22c1ea64011516b25952a2d96b63d17d3379b3cac6
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165695);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2022-20769");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa40778");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wlc-dos-mKGRrsCB");

  script_name(english:"Cisco Wireless LAN Controller AireOS Software FIPS Mode DoS (cisco-sa-wlc-dos-mKGRrsCB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller (WLC) is affected by a denial of service (Dos)
vulnerability. An unauthenticated, network-adjacent attacker can send specially crafted packets to an affected device
causing it to crash.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-dos-mKGRrsCB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?097704a1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa40778");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa40778");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20769");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['wlc_fips']
];


var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '8.10.171.0'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwa40778',
  'cmds'          , make_list('show switchconfig')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_ranges:vuln_ranges
);
