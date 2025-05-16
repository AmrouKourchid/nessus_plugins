#TRUSTED 6fea9fa26ff9c32f4aa95a09a3643adc1ffecd86858824ce0281c50a83efb15f4bf8336cb4fd17cdc2da7231b1b7cd22956ef7deddf4d3d6baa62698958ceed3e557763c02784e49bb65dbf8d122e5212a535a55ad76cd79cef4375eb69be89868d92693d0a65c99f15974919e28e08d15a10b2fcdffac07d9a56623c2be8c4915a30c5486c6cbd4f2ca691033d2e15c9d8b6e16ad3d02d1462c32444f481ad9e8a531c6bbbbdaab64e0fe7702ce078d9ee9f6073c8596b60fdb0b71150700ba4d54f7cb1cfab3842f0ae068a097e07e994592b3ea0f304cb9cd61688d2004a0c1be1c8f66bda17f969fd40a508636560d1a8b0b58c7ba22ba5fedd5ef4b2e473424297f7381f32a17ae0e2321c924610a9769b180fd2c52ff645496a777591398d03c2834179e4925979653a8dff1c71aeb89bf7829c2cf91b7ff7f923e18831cd261fe7b022f2ec966d812666d24d2fb2c17b5d4b8186644b3c386832e6925c48d03b2c725342f16c00b992e57dbc5d036944e743fa92358e3c3196be42d3b203590c35ece2c8c5a9d0e9e3182017063d6b6a02b5865e4173f0335683d4c2dc7e9261171b0896015f002ed9feddaa1059fbadb49bf1b3a5d98a443c6af81904101da87bb70ff64d6f51a98df8b33871a5cff7502150fa495a2ab86aa3ee7c2f79a133855eaede3edb56a70fb2b2e9497b3fb0879b0ba3226895557db78d36e
#TRUST-RSA-SHA256 7e0219bee3c92179e1308a560bf45d05758f236bf18896611ed4e35fc97e32bfb263a5a31b7a71beb9edda54e84dc219eabb3ffb1f30152be20266e16012b56fa8603c8bd3937528b16577d2f13cb6fa12ed3f2081c57b446d0a4b6a8492066da096f2380c7014574465081f3354c2d76aa40ad3996f2fcfa3664b720ed5179873c0e78340c2ad533049c0c55f0c2e9dfd3624c177f42ee9b47b3d5f91a7b36c332f8cbb1c0ad21ca67ee181c8fb1ca32459af90db592b4623ff6a7c158e69caf6e995e37f30b796c259c55f225c91f2d90fa2217663c0ff18a00915b0e23cfee978a2277cd850889078cd4b346ccfba942f4bccf3ebb9c843f562a970875e0b068ae01177d04f35ce3c1a3296d3905afda893ab5682814054333a340ecec053a9c6c06b049a204ef66eb132de11c65cdcf6578c262524163add3bd5b012c197e9530943e44fd1ea19e6843cd834050b4f46343334e63bccbb5305e839cbe00abe10dffac6c1ae9ad0819850eb6657bd780210826bbafb080b0239c10c665071b8ac5c911c239523b5068c02fd39a889dfa16963e2ce3a7f1bd21e015820bba7cbac5e1acbd9b6e61448fe58e69e9f864b6af30b6c1f4ca96809de78b47fc734242f11c40f3906ec9d1eb0ebf17b5bd8179959e7801f2023f04488a3c77317c8bca8be253c174d46ba1538109460fbe7962ea6004329e8a868e14e6487fa7592
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132317);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/12");

  script_cve_id("CVE-2019-6693");

  script_name(english:"Fortinet FortiOS < 5.6.10 / 6.0 < 6.0.7 / 6.2.x < 6.2.1 Vulnerable Encryption (FG-IR-19-007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of FortiOS that has not yet enabled private data encryption.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS that has not yet enabled private-data-encryption. A 
authorized remote user with access or knowledge of the standard encryption key could gain access and decrypt 
the FortiOS backup files and all non-administor passwords and private keys.' (CVE-2019-6693)");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-19-007");
  script_set_attribute(attribute:"solution", value:
"Ensure that Fortinet FortiOS has been updated to 5.6.10, 6.0.7, 6.2.1, or later.
Additionally the user will need to set the private-data-encryption attribute 
based on instructions contained in FG-IR-19-007 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6693");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin", "ssh_get_info.nasl");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");
  script_exclude_keys("Host/windows_local_checks");

  exit(0);
}

include('hostlevel_funcs.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

if (app_info.version !~ "^[0-6][\.\d]+")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, app_info.version);

constraints = [
  {'min_version': '0.0', 'fixed_version': '5.6.11' },
  {'min_version': '6.0', 'fixed_version': '6.0.7' }
];

report +=
  '\n  FortiOS is currently running a vulnerable configuration,'
  +'\n  Based on private-data-encryption is currently not enabled.'
  +'\n  Please ensure private-data-encryption is enabled.\n';

vuln_settings = [{config_command:'full-configuration', config_value:'private-data-encryption enable'}];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, vuln_settings:vuln_settings, report:report, not_equal:TRUE);