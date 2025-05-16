#TRUSTED 4b128c9652486034cdd3790510f2f0e70b8496ec7dfb016ddf4a580fdf89db135935434a7fa154a3287ef290cb66ebb3232d403e4867ea1091e083440adc8d6d149efb8e5e9b758ae962d37037a852a457cc41ec145961a8c9dd982c33a12425789a312185b480ea4f416c8482f69def7861a3ece3411f25efdd377bb46844f0964f46435c5ebfa931200a49a77f38c80eefbc735978886c89c98724533ce16064123bd346eaa744408f6929d8d478d0d958141731f115d756e3c61167d2c183ec90e21e91b84d6e60c9ee7943a9a05ec78037a294e95dbe47660e092c2b7223d2dbee04dcf9cffeb6fb28413d1c0dc7e41cef100e11ead43651792c8268a8fa4dd673b401213f175712bbae8af2b56f2d5c1b30adf50c355f973fda784499b53be95b0a3d44b32fb7689e74d53e4434d00c410b6e49193ea8a6039b608bf0ee8ed3feb91028277ac01f8d0a8a8e443fd3a7b5471d47239838d70571586af1d4c4af32dad4f6940e14c82adaf07d557ccb9f3070fd79759960bb1e4561e12a5d71c18603a46a269ae6d9fd4d8f4acb7f62cb95cf800090c5e81dcb04bb3e3239d257a89917e9eabc3420bc517456c97bf716119ca881a73e61318fa935faae0daef04e247a5a9730b625e6756cb07b4b1ff752f5c2ce15a87d323b208ca242e92b4fe2e4748647a5731787fffb11178f1e31558385927a938106233896af814b
#TRUST-RSA-SHA256 6a3b6c5d42de101eeffd2a38915def3a47f526ecb8279894a788379a95e2686661786686798f1b2f75d5b5569817f10c010e67d3da5858a1dcad268c1ea55b231a68b2bd30025471d0793e14d0b6bfcb89e46bd1af61b4ce5df64adfe98442bfd7d48b11768a93465a3c62d17a75daf6df1a6073a141e9d058678cb89ed80840e6207abecee3732938b883dca510c9b67ea3c1f5df9b6adf99a7ebc79d84739e58544fd7ff44ff09982b8a9f56c7ddd59abeb0c6d9bc0cb6092e9e3a50ddcc955480cf6d922538643ae3d3732a0b416f871558328a4a37201256180766fd3e5ea64ab151f4ea8e86fe4b0d79d1b46d7ef0233116ff0aa2cdfa05a0b9a333b272f864c2184c4baded8f227d2de4716211b1e33b8982b1a6bc25e6f8f2c05fb07de91b66b31d43557fee5a7da9caa70fa10c555e0b63e3543605cce704cbc9a094f5421acc9de226ad49bec9e44db6604590f7cc23716f37a3e70533ac7b575e8f463ec98d81332dbb8e45b4badacfc2384abcbf726fc348ff965fbe6947f2002781d8a2a5325e06f5bdde67837082987b0656c662e8a700e15c3949d42b20b6d6d228d27b0a0ba5e8ba9df69108043dbef54b7184e9e4dcccc591ce34b3cc67d3a33129fbf907076cf29202d3e106f164e99f765bf96f8a47fa3097c9dbabaa90242ac378a2783840817eff7800685aea1c662133cef838128b33b8ba0fe340d2
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148106);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1453");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw36680");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-cat-verify-BQ5hrXgH");

  script_name(english:"Cisco IOS XE Software for the Catalyst 9000 Family Arbitrary Code Execution (cisco-sa-ios-xe-cat-verify-BQ5hrXgH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-cat-verify-BQ5hrXgH
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01d217cf");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw36680");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw36680");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1453");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if ((model !~ 'cat' || (model !~ '9400')) &&
    (model !~ 'cat' || (model !~ '9500-')) &&
    (model !~ 'cat' || (model !~ '9600')))
    audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.6',
  '16.6.7',
  '16.6.8',
  '16.7.1',
  '16.8.1',
  '16.8.1a',
  '16.8.1s',
  '16.9.1',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '16.9.6',
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.3',
  '17.3.1',
  '17.3.2',
  '17.3.2a',
  '17.4.1'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvw36680',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
