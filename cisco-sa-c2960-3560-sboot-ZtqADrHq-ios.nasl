#TRUSTED 25be54e9499bdf4a628a14f96f928352753effc7240d1d2b3d40b80df86e4aa5bb972e68e794d6b0ef901f14a0eec6ca6e5e9453ba4445bc742675732faab1915c18f41d28a3c78784407e4359c5acd59ee4d58d583b1ebaee94d015d89a4c8ef24d02b1a8ed12b07ab48e2965f9d45de4939327ac3ed8584568060be86a911304ef4c842c680817ecb715bab0239316240ae572ebf78dbfe539372dcc831b2d81ff90759f036f5f5d9b4cb7559a824ac4a9d406c07a100958792d1ea30476b82b917c246d9c6846867bb1fa90987832d293828efc9da1b55ba1c7ba409e16005897f303364eb9d1de1261a0e2cc8f214302a902578e2cc8d390647b8f1387d3614dce5f90f32d047556b323b93b8d043056413c5b7d776054a81b57ba4a45dfcda1205d1c3f913fc063032f4196ad750fe404d2ff642240a7a36a5863d233e9e5373230b6047befd349419c59fdf6399573c14d751d69be2607985496a77a32d4954452b6515a0ed38cdc36987cc754a78c687dbfecb58149eb4312aac0884560c7ac51d543e239ba46473f80f51c825aeddc85714f3aaa731d5df8d5f7cc8b55c2f947f378eeaa4d70d84a79260fe5b4fb63a9f87cc38d6cdca880363a7e288d08527afcbff6797b4a9a98f9f89a1331d6ab169fe96510afea72f79a095b7b014e15c5fa0cddd1234b9781287a3a2aaf4c4c799d3c55b17600ba1a75fe97ad
#TRUST-RSA-SHA256 035dd978a99cd657856e4ac8a33c4e3d67d28db7df2220c79c3616c8d8c9abb260c798cfec7c8dc509e8660a656b6ae3f301280383a07901f3127b9816cdd542b727aca5f090c79b0975fbb76059465c444a785de81497f02eaf9974a48281f684184bf18d008eb91631a83780fed857ef70858590f5942e692477d0bdbc0f884282fa4c49c7cdc25ff39cb5713173dacca08d6f9858d1cd770db4093516099d9053ec2621217c0ff88247d402f5163e6fd4c8e93406a1dd5e936fbd935e11dc3cd09997e788943af8e06005c86f0e4f4ee8b85a9c34bb752e62d8b232eab3d9c23d0d1f574f48fe7ac31a8eb97c354e7507b077fc6c8a9a0b010f458105e7f9e93d84c0d1ba27c23cfdb0ed3243ac6b8508e74e04e449429b4af0f262cd624eae2a149189bb8f5d6bfeda179e43db90142a1e21ea11d00058ad19411656684f8fc9ab02a822285e1facb7d89e1ffffbc1b1e2543703e0a85d989feb0e9d849bc08e9e2492c6438111df7c6a3e3ca1c2dd0a5a488d78c1fc2bf09845a7bb70eb49ef5bfdbafbc23176a33b1fefe8e11ae4ee35eb24631148a2f8d8b04781410d1b33b3c19ba76a230fdb8f6d29d865e9ab830b51760d1ec3b104108bb97edb135c4bafb8b94bdea511aa31d84b44adfff5d02d1d204d43ff6a2b76413bfe908056d617526466f199155db9b35ea2770e95db48ee8bd68ffb6cf0ee321fd1b8fb
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235487);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-20181");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd75918");
  script_xref(name:"CISCO-SA", value:"cisco-sa-c2960-3560-sboot-ZtqADrHq");
  script_xref(name:"IAVA", value:"2025-A-0318");

  script_name(english:"Cisco IOS Software for Catalyst 2960X  2960XR  2960CX  3560CX Series Switches Secure Boot Bypass (cisco-sa-c2960-3560-sboot-ZtqADrHq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a vulnerability.

  - A vulnerability in Cisco IOS Software for Cisco Catalyst 2960X, 2960XR, 2960CX, and 3560CX Series Switches
    could allow an authenticated, local attacker with privilege level 15 or an unauthenticated attacker with
    physical access to the device to execute persistent code at boot time and break the chain of trust. This
    vulnerability is due to missing signature verification for specific files that may be loaded during the
    device boot process. An attacker could exploit this vulnerability by placing a crafted file into a
    specific location on an affected device. A successful exploit could allow the attacker to execute
    arbitrary code at boot time. Because this allows the attacker to bypass a major security feature of the
    device, Cisco has raised the Security Impact Rating (SIR) of this advisory from Medium to High.
    (CVE-2025-20181)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-c2960-3560-sboot-ZtqADrHq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36d09f82");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75279
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?564dd2a1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd75918");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvd75918");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20181");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "2960CX|2960X|2960XR|3560CX")
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '12.2(6)I1',
  '15.0(1)EX',
  '15.0(1)EY',
  '15.0(1)EY1',
  '15.0(1)EY2',
  '15.0(1)XO',
  '15.0(1)XO1',
  '15.0(2)EX',
  '15.0(2)EX1',
  '15.0(2)EX2',
  '15.0(2)EX3',
  '15.0(2)EX4',
  '15.0(2)EX5',
  '15.0(2)EX6',
  '15.0(2)EX7',
  '15.0(2)EX8',
  '15.0(2)EX10',
  '15.0(2)EX11',
  '15.0(2)EX12',
  '15.0(2)EX13',
  '15.0(2)SE8',
  '15.0(2)SQD',
  '15.0(2)SQD1',
  '15.0(2)SQD2',
  '15.0(2)SQD3',
  '15.0(2)SQD4',
  '15.0(2)SQD5',
  '15.0(2)SQD6',
  '15.0(2)SQD7',
  '15.0(2)SQD8',
  '15.0(2)XO',
  '15.0(2a)EX5',
  '15.1(3)SVR1',
  '15.1(3)SVR2',
  '15.1(3)SVR3',
  '15.1(3)SVR10',
  '15.1(3)SVS',
  '15.1(3)SVS1',
  '15.1(3)SVT1',
  '15.1(3)SVT2',
  '15.1(3)SVT3',
  '15.1(3)SVT4',
  '15.1(3)SVU1',
  '15.1(3)SVU2',
  '15.1(3)SVU10',
  '15.1(3)SVU11',
  '15.1(3)SVU20',
  '15.1(3)SVU21',
  '15.1(3)SVV1',
  '15.1(3)SVV2',
  '15.1(3)SVV3',
  '15.1(3)SVV4',
  '15.1(3)SVW',
  '15.1(3)SVW1',
  '15.1(3)SVX',
  '15.1(3)SVX1',
  '15.2(2)E',
  '15.2(2)E1',
  '15.2(2)E2',
  '15.2(2)E3',
  '15.2(2)E4',
  '15.2(2)E5',
  '15.2(2)E5a',
  '15.2(2)E5b',
  '15.2(2)E6',
  '15.2(2)E7',
  '15.2(2)E8',
  '15.2(2)E9',
  '15.2(2)E9a',
  '15.2(2)E10',
  '15.2(2)E10a',
  '15.2(2)E10b',
  '15.2(2)E10c',
  '15.2(2a)E1',
  '15.2(2a)E2',
  '15.2(2b)E',
  '15.2(3)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(3)E4',
  '15.2(3a)E',
  '15.2(3m)E2',
  '15.2(3m)E7',
  '15.2(3m)E8',
  '15.2(4)E',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(4)E3',
  '15.2(4)E4',
  '15.2(4)E5',
  '15.2(4)E6',
  '15.2(4)E7',
  '15.2(4)E8',
  '15.2(4)E9',
  '15.2(4)E10',
  '15.2(4)E10a',
  '15.2(4)E10b',
  '15.2(4)E10c',
  '15.2(4)E10d',
  '15.2(4)EA7',
  '15.2(4)EA8',
  '15.2(4)EA9',
  '15.2(4)EA9a',
  '15.2(4m)E1',
  '15.2(4m)E2',
  '15.2(4m)E3',
  '15.2(4n)E2',
  '15.2(4o)E2',
  '15.2(4o)E3',
  '15.2(4p)E1',
  '15.2(4q)E1',
  '15.2(4s)E1',
  '15.2(5)E',
  '15.2(5)E1',
  '15.2(5)E2',
  '15.2(5b)E',
  '15.2(6)E',
  '15.2(6)E0a',
  '15.2(6)E0c',
  '15.2(6)E1',
  '15.2(6)E1a',
  '15.2(6)E1s',
  '15.2(6)E2',
  '15.2(6)E2a',
  '15.2(6)E2b',
  '15.2(6)E3',
  '15.2(6)EB',
  '15.2(7)E',
  '15.2(7)E0a',
  '15.2(7)E0b',
  '15.2(7)E0s',
  '15.2(7)E1',
  '15.2(7)E1a',
  '15.2(7)E2',
  '15.2(7)E2a',
  '15.2(7)E2b',
  '15.2(7)E3',
  '15.2(7)E3k',
  '15.2(7)E4',
  '15.2(7)E5',
  '15.2(7)E6',
  '15.2(7)E7',
  '15.2(7)E8',
  '15.2(7)E9',
  '15.2(7)E10',
  '15.2(7a)E0b',
  '15.2(7b)E0b',
  '15.2(8)E',
  '15.2(8)E1',
  '15.2(8)E2',
  '15.2(8)E3',
  '15.2(8)E4',
  '15.2(8)E5',
  '15.2(8)E6'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvd75918',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
