#TRUSTED 8a8812c8728873180dc02c44fddfdea6b792ad39c8d35df701aea43e15b52d9f826ad98561da18dda50b2cf681482f762f8616e69cc1964500c215ec3fc235c4423c602420ae404e286d028b8d1ae7af5c39df1324d066e66c9ba26102dbdcc44bea9002fc313ab286fa239afcaaa78beef587a72e2ddbf4503852c9f307181c450d20c12182e49d1942c1d5ff7ed4ad4dc01c31ec71492e034fbd5bed8eb3e7bb174e9cfda91dca27c911b21a771e96f02aa2740e081669f31cebced4a3d09b0e445549ef59227e8e66150c073b4e72ca7d9348aeb5fcd05bdb124323ba92b2380fba3f542bc259999632ce57c1b265b20489f8ad60648b76e9e770a554ba3eb644aadd2081c26bcb0469c1609e4ef264d7ff797ccee7ab2bde08def33308d6e066d33878ae1edafea6f37b3348c8edfe24df8eab77ad18b438f32108b13b6f2dc8f42d6ef9e2ba858045221ee88eef672c58af56123b113c19c6c191c17f7f1022dc9968e56bd933712871bce457588d4832c370182a9132996843368d4b0b6f52464cc87277f2651c6753ebc3103a3f9687e0427dc39fbf91830e1c33abda22ca35145b65c01468c0b1a6dfa707bfda2b9e72dd8e72d133fb2ca953a35b7914224c5012c2b893e59a945d04064e9361e480d94034e527be48f1d87154cbc46629046a5049097770e455592f7f3d17c222a0db77a8b82235081cf3c29d60bb
#TRUST-RSA-SHA256 4a00e9d7f06ceb5eaaf615bad2e7d33be44e2ae339f5cb99ff50e32a420ae8b38304575c3bea5a362fbf2c2b157dd8a4b058b37bf0fabbce4d71eb3a342b74e083e4749ce1b5b71a36838f363d1c25d84efb316900bcdaad5185639ee8a798e9a0f43504894afbc3e338c529e28879a6bb4a5197985a29b8d62793d90046e3ec6a7af3c7681d713f8c950205b1bce3d9178572842bd92fd9864bd3c5756a3ce71928cc8eac521ed062acff4fa6b2fff084ce09e7f54d122e71b40a07ed9e87ef82d02ec9882371533f8b6fb494840f7c862c28d924765a1522d0c118bcf5900f29e235a070e8b86fd2f45f96ccad99a6793f384448b8b0e15c242dd7dde99ec3f12a2ade3773bb7765374f696b3bff95c2b8c11de14c2cf18bb9adb40a5f54c47e049be9983a3bff3579df33ea771e53e615b7b30f58b3cde01b82024991d628cd6cd7bd9d7b5deaa407783c053d21c81a3274a604a537235888c984a2edab4ca3cf87687bed5bd716e2497afd1a621d79517e65edb6b16b2992aca52a21bfd767739a6145e5e4206430641c1b00cb49b6f9bd69cdf48f471aa93a0093dc30d44f9a82d64188a3c338a93ba55c740a0a06ef9c0186ebaad0998335d520950c4ce55c980870de5941d0014445c9c3961f4cc16d2c7ae3cb1d1dedff9b49bdcd66660741437a17e57d97b27b636d821263a55a018f4be6cd8cf46df274a5bd9db0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124172);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/26");

  script_cve_id("CVE-2018-0296");
  script_bugtraq_id(104612);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi16029");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180606-asaftd");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2019-0741");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Cisco FTD Web Services DoS (cisco-sa-20180606-asaftd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Firepower Threat Defense (FTD) Software is missing a vendor-supplied security patch. It is,
therefore, affected by a vulnerability in the web interface due to improper validation of the HTTP URL. An
unauthenticated, remote attacker can exploit this, via a specially crafted HTTP request, to cause a DoS condition or
unauthenticated disclosure of information. This vulnerability applies to IPv4 and IPv6 HTTP traffic.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-asaftd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c235f451");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi16029");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20180606-asaftd.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0296");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'Cisco Firepower Threat Defense';
app_info = vcf::get_app_info(app:app);
product_info = make_array('model' , app_info['Model'], 'version' , app_info['version'], 'name', app);

ver = product_info['version'];
model = product_info['model'];

if (
  model !~ '^1000V' && # 1000V
  model !~ '^30[0-9][0-9]($|[^0-9])' && # 3000 ISA
  model !~ '^55[0-9][0-9]' && # 5500
  model !~ '^55[0-9][0-9]-X' && # 5500-X
  model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  model != 'v' &&                       # ASAv
  model !~ '^21[0-9][0-9]($|[^0-9])' && # Firepower 2100 SSA
  model !~ '^41[0-9][0-9]($|[^0-9])' && # Firepower 4100 SSA
  model !~ '^93[0-9][0-9]($|[^0-9])'    # Firepower 9300 ASA
) audit(AUDIT_HOST_NOT, 'an affected Cisco FTD product');


if (ver =~ '^6.(0|1.0)' && (model =~ '^41[0-9][0-9]($|[^0-9])' || model =~ '^93[0-9][0-9]($|[^0-9])'))
  fix = 'Cisco_FTD_SSP_Hotfix_EI-6.1.0.7-2.sh';
else if (ver =~ '^6.(0|1.0)')
  fix = 'Cisco_FTD_Hotfix_EI-6.1.0.7-2.sh';
else if (ver =~ '^6.2.[12]')
  fix = '6.2.2.3';
else if (ver =~ '6.2.3')
  fix = '6.2.3.1 / 6.2.3-85 (Software image for FTD Virtual for the Microsoft Azure Cloud) / 6.2.3-85.0 (Software image for FTD Virtual for the AWS Cloud)';

vuln_ranges = [
  {'min_ver' : '6.0', 'fix_ver' : '6.1.0.7'},
  {'min_ver' : '6.2.1', 'fix_ver' : '6.2.2.3'},
  {'min_ver' : '6.2.3', 'fix_ver' : '6.2.3.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , ver,
  'bug_id'   , 'CSCvi16029',
  'fix'      , fix
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

