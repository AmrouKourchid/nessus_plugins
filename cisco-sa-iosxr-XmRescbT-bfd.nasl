#TRUSTED 4e3ee062a58007d669d26a53912c63cdaaf2a3923d331feeb62d3b63ce89b21ea33041222db78490cfe1942114d41bc4a709fcf20eaabee25daa43603fdb8251476de37061590cb50a28bbe3fe2e3c225ffddbca57ac1127c639ef2267fa3c6804e790c977501ae343e206ce349ee7cbecd76ff122d941d02494afd70766619ce4a0506114629bc58fde06f8764b2bc3b71bb34c27b74436edfeb378829b32315783e83c8ce070111b84cb2021eec2ef21091e79b177eafc87fb4c7e132da10d8fee81b0b376df1619fd35782eb76f3468c4f06db22cc8836c095c433dcca13552baa5d5c548cbc6343736c47a3763e7211ef900d96e64ad05407ed51374b72fa16c0c69b28415bd9f205a830230ba6e976e69c340ed4428c0fdefe4d535ef897d4c97b22f42b9ea10515ec09d82416ca23ff35b5f2a1d05e9256ef7b54251f33919554245eb8407544f22685fbf8ab462b4026be3ce545d3a2c42099e92be67c37b39327d964b36eedec35b0f1690793bbb41e4228ebbc48cdd6f8acb5c8edba416608c25223ddad08975fc64296998e6be0732863e94b6ff883ca9d44a46618b360dd537e1f470058068a41f6f90d9ecb8315c5875d59540087de5647a04282cb615bbc708b493c210106513a237a5624785419d8ec572a4956b425ebdff8c40e587d1fbecd5c6ee3d8658aa2500d8037976941678bc5e2a3f3b2fdaf4b345
#TRUST-RSA-SHA256 9bec055b24566b36b0152c38163765135a43e2354e75fb0b872c95b6fb43fbe395f26033dd3e7fdcf2be0a18dbd8ad79f75fc3ac2eab175e5d8a24b10b6b7883907169ebc7daacd764761dccfc7dd7cfac6ec256a13a7dee6f29f784bda4ae419169fd2220f04dd849cca0065b79479f3cfe44f7c79f77d2b23dcbacfe4a71ac092d1cd9c533f73166d873ba589a38308ff3fa4ac45511fc82bae7eb2b82283d48d0cb08ed5c448c107beca594a810db211777cb423007655af72932644c936fd8e5d41640fc8b121dc0c46a155cee8728f751691bb316a4c73ae6723aae5bcb8c7abe007f01ba0fcc73dedf03ffee525ef943ba2ba5ed6d58807d4d24ce4b4efd0f290af77eab26d0f05c51cdd7708ca6b3b28eca7e46bd5722b1f832ddfbeb76ea3619c686025089ce08f76d5dab599ab7a638821da19421523025bd0d0a75b5096477e5b90c311cdf88af669eaaad357bb5406d31f28d20137d2ef1f7a6e7c2b2ef8e0275bafbb06e67527ba4e3e5e666962309c7b7eb98e14cdf1faec9ec9c2fc303db0acbcfb443d21fd4b94823fcd34455b0f3e5c183198c6ea8c24e8e3c322b4476d3362f1344cb4de2840eb2e3d4d8757613f7720320e66a3654a1f0598c36bfb12df652a0800e361929680448421ec5e403e248ef5503d09a4e50540c9a75be243c29372264d07e6903529667c8c7d4c1ce8301865535ffb50dfe0b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173737);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/01");

  script_cve_id("CVE-2023-20049");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc39336");
  script_xref(name:"CISCO-SA", value:"cisco-sa-bfd-XmRescbT");
  script_xref(name:"IAVA", value:"2023-A-0126");

  script_name(english:"Cisco IOS XR Software for ASR 9000 Series Routers Bidirectional Forwarding Detection DoS (cisco-sa-bfd-XmRescbT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-bfd-XmRescbT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50e462c3");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74917
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6d11e40");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc39336");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc39336");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20049");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);
var smus = {};

# Vulnerable model list
if ('ASR' >!< model || model !~ "9[0-9]+|9902|9903")
    audit(AUDIT_HOST_NOT, 'affected');

if ('ASR9K-X64' >< model)
{
    smus['7.1.3'] = 'CSCwc39336';
    smus['7.3.2'] = 'CSCwc39336';
    smus['7.5.2'] = 'CSCwc39336';
}

var vuln_ranges = [
  {'min_ver' : '6.5', 'fix_ver' : '7.5.3'},
  {'min_ver' : '7.6', 'fix_ver' : '7.6.2'},
  {'min_ver' : '7.7', 'fix_ver' : '7.7.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['bfd_enabled_in_hw-offload_state'],
  WORKAROUND_CONFIG['bfd_enabled_in_all_session'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwc39336'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
