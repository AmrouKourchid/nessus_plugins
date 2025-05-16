#TRUSTED 5976ba4637367be0a2e4721e615b70d93491e773d4213fcac57f762ee5b47e00e0ea63918a57bfb3314b7344f74b5e853acc98728504e27111450d8d7e56948dfc31a6369d7625ff5751bf3a1e3da25c91e4b387e34188b8112f76367c9f1300377910accdc09d8c6e8d7ed97e6533239689461a7a4c0fa88d7e00a979eb5b523f8a24eed3001706f02059dbe3f405d949994e9da2d830743723757878f6f45090a649165ea17618a9507849dc0d305a8894184196cad1791d3029f608b5fb65bba44c72b415e8993088a5a7cf8309e507e5b592e8b8f8045c115b71a40b71ab1d6fe84744df80dff1c575744a30fb6c02c98309d351de8636155f1db2bed9fc1641d3f8af8b2c00d049c29a702b29c655554abe6faf28b48873b7705c28a033e1d078506e3fc6fe92c5a636157d917a408e6cfe5e93d91a08e5e0a3b3b0364c8fbdf6b201546b47e484ed7731a382f2cf7b259f1fdadbe2161cc84cfc1472d2e94d90593dfc13d4b00d5cf9e734bbfcc65d695a46806b70a5b15fe6657927630fc37d8644e2785c1e001cc585bb9192f71b4f2a4f0cfeebfed43ebdff93019e898620fb2f5dc166d942f3b7a7d2684920055900d591edb2908c90617b5e10dd2f4d038e83db9189273b1c56682f6c3e5083f18f7dc38a1255cd63c59e5abe2aa4a4f3d7dd8b377e7e59d2311b58710ccdfb8b053af9b9f20126075f2778569a
#TRUST-RSA-SHA256 7553cf842a940d122123d18f546e675fcee6549554f92a53a7ee51aed4c35c1314e194f5442769cae6f457feb30ed073c219a86b7a93e978e8adc70fde93be4cca8e3205a85086aefd4a933bedb000e509b2cd035b20b234d377e0ed86e5d264bc7b52fd8e4a76126fa7a961bd59fea772f4965fccbd966b28f19341628da55fe901b320a1fd4e6689896b3b6ea16f4ba1cfda2b92cd68ea4bfc3543d506d2691c63d03312e5a06a33cd8d059a6431c86d06a23d7323df44eae6dc66b7beaa41240909718307a9f597b50350a6538661dcd218ca3d808133aab5fa73082d5b971719ed0e70fbeab608254e4963361183e2ad34db39f4a816c85901a0757e391fc375bb52fabfbc7c6b9b64151676f333ba0d5ce495a1c22b258c0a949dee92f7e347c9152aabdebdfce68cd0f87935a5aec0813001c8206504c8cdd1081f3ff5486202c6d03a2bd01176a21eb719bfb33bf69fdacb5620e643ebfcef46448ebd448f3d66764ec134500c0158d0fa27cc525dfbf901cf0d0b640644aeb13f39ccbe885573a53c72f9b7bddc61aac0fe9ce3e666f3d37315341618d2da259163850a0a9fa600b584e4fd1db49bd9370997a92176a1f43e731e50c14d36ab6a4025e3b16107c79809ce21336d570a717e49b42903ecea1f35ec4f295bb6e7a56f689f07aaa059a15599b5b4ffbadd9b84245be988cd63eb2fef06a7675b355f976f
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161865);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-40114");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt57503");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx29001");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort-dos-s2R7W9UU");

  script_name(english:"Cisco IOS XE Software Unified Threat Defense DoS (cisco-sa-snort-dos-s2R7W9UU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco UTD Software is affected by a denial of service vulnerability. A denial 
of service (DoS) vulnerability exists in the way the Snort detection engine processes ICMP traffic. An unauthenticated,
remote attacker can exploit this issue by sending a series of ICMP packets which can cause the device to stop 
responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort-dos-s2R7W9UU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3be003ee");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt57503");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx29001");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40114");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(770);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# can't detect snort currently
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Affects Cisco ISR1000, ISR4000, CSR1000V
var model = toupper(product_info['model']);

if(!pgrep(pattern:"ISR[14]0{3}|CSR10{3}V|CATALYST8[023]{3}", string:model))
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  {'min_ver': '16.12', 'fix_ver': '16.12.6'},
  {'min_ver': '17.3', 'fix_ver': '17.3.4a'},
  {'min_ver': '17.4', 'fix_ver': '17.4.2'}
];

var reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt57503, CSCvx29001',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
