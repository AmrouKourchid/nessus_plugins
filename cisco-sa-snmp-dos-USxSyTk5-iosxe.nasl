#TRUSTED 0e427ad0ff39e5248d03f2cd0b6e3a0c6861678be172e2f38559b3aaff1fae84a5e402aae537671aa401937d02b5eed17a760110ba7cb5000555910b740fd667fe324a75e00687f3783dac479c357ff7791d6db7d09ce9988ce2657ef9a00d98af874c2559e243765f84cd4f383cebdc79d244182eb65293c98e20b662093e22ecc823d44bd197cf219b1b397400992978cbd74219030d8d5cc07d52ab1ed5964abe7e8cbfbbc2dc292fe0880cbbc9a2fd0b74a927efd8e33a51723d639dbe26a07ed568f65d4902e2f929ffaa6d0f9ec525e41716678b826f015e9cd553d86265365dd31d6fea5a53c073fdc4f97c64f3a88522396cb5ec5d7ba9a6d262ea447f7b336804bff341f4fb54cf62d1d12a38777182d4f652ce78a7bbe973e02d29c7564d146ce217018b5217a82d97f986f9aeb135d444fb4df0e23df471145bf5c58bb65b671df0e943d3a283ee290eb15ef0dcf7992bed17c16e113af2b972a040aa6e5dd7ebf18c194b1c198effafbea3fdc6989194c17b4512540315e0e1044219619f83bc2f3a57e6fdc58ce04c8fe0bce7306944ee84cd1f529a76b840e39a500092340bca4b48d95d9ad438f5e4808471dd570e60656b008c1c9d8034c9fb111a7a2e6c768ae75da56a6f6f0d4035a8994c1cbfd916d7fd79286385b800ce0af466c435910355e5bb0439a8be16a32bccf5844cb71427fb549816c6ab5b
#TRUST-RSA-SHA256 9e2b0b2a127df937c2975b99273e07dbd21bc4db2735db94257832be8eee061c441c9426033b83e1db0ccbda29f635f27673d195495e59e7f282400285833bfc93ad47bd6df8829258e1868004410fc0177d978415ecbd34e3d2e94872bcc25b0b873a76e694d74ee8828c1031e3a5e2aa626d1e2635abaf88e7ebcdadd574da0249f0fd10f34a2d61db5e1e1b5f3eb34049ae671f1a1536c56c2b9b7e0e157989eebcceb2d96eecf2e954bc83888866a173ad24ab60ebca38579e55dd87f46d1a19454dc8b4f58f5fe6c0665c58f529350621d77af9ac33cd264b955ea5fa35238278d020e412addaaafc2cec65e3de1463b10c03f4097f94471e682204b2d42179a8a0983d8ab9dc6a84f51b662099d903feda57e43767df8e68b89993e8494d68fd3709b1a9e3a0d32544e6d0427457eea61b28705a9eadf265f354a52bd589b43acaf759d4a6be99419e9661d9acb6cad249cb879e9fbbe4eb850018f5e757ccdd8cf47b876e49a32c1ebcc26b3b52a0e9517f0a9f3fbd7735bfb3d9b902f2c9a89e3b7ff9c976114fb348b89e197d80abc4523ec61abe8c9dc846540997f95723a9d2a6e7cd28d01ee73b66bfe61378c518a270a5b6cccfa60e8a7ac602ffe4fedecfe782ad313c7ce9bd1f8557f8cd74610a003dfca40ac05e5f9e421aebec969bef2b26d09a4e9e7dd153dff8a0cdc070193ecfea5b0018aa5592055b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137145);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3235");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk71355");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snmp-dos-USxSyTk5");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Simple Network Management Protocol DoS (cisco-sa-snmp-dos-USxSyTk5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software  is affected by a vulnerability in the Simple Network
Management Protocol (SNMP) subsystem due to insufficient input validation when the software processes specific SNMP
object identifiers. An authenticated, remote attacker can exploit this, by sending a crafted SNMP packet to an affected
device, in order to cause a denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-dos-USxSyTk5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?528a5571");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk71355");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk71355 or apply the workaround mentioned in the
vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(118);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

if ('catalyst' >!< tolower(product_info.model) || product_info.model !~ "45\d\d(^\d|$)")
  audit(AUDIT_HOST_NOT, 'an affected model');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

version_list=make_list(
  '3.9.2bE',
  '3.9.2E',
  '3.9.1E',
  '3.9.0E',
  '3.8.8E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2E',
  '3.8.1E',
  '3.8.0E',
  '3.7.3E',
  '3.7.2E',
  '3.7.1E',
  '3.7.0E',
  '3.6.9E',
  '3.6.8E',
  '3.6.7E',
  '3.6.6E',
  '3.6.5bE',
  '3.6.5aE',
  '3.6.5E',
  '3.6.4E',
  '3.6.3E',
  '3.6.1E',
  '3.6.10E',
  '3.6.0bE',
  '3.6.0E',
  '3.5.3E',
  '3.5.2E',
  '3.5.1E',
  '3.5.0E',
  '3.4.8SG',
  '3.4.7SG',
  '3.4.6SG',
  '3.4.5SG',
  '3.4.4SG',
  '3.4.3SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.0SG',
  '3.3.2XO',
  '3.3.2SG',
  '3.3.1XO',
  '3.3.1SG',
  '3.3.0XO',
  '3.3.0SG',
  '3.2.9SG',
  '3.2.8SG',
  '3.2.7SG',
  '3.2.6SG',
  '3.2.5SG',
  '3.2.4SG',
  '3.2.3SG',
  '3.2.2SG',
  '3.2.1SG',
  '3.2.11SG',
  '3.2.10SG',
  '3.2.0SG',
  '3.10.2E',
  '3.10.1sE',
  '3.10.1aE',
  '3.10.1E',
  '3.10.0cE',
  '3.10.0E'
);

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvk71355',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
