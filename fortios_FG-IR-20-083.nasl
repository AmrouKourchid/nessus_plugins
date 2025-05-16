#TRUSTED 456219786f39d2e166c07af033a2ba375f0a4c0ad5779020d4f182740503f6b829d569e7e844a913d7f06dcef417a3ace44fe17f2b0d6f74fc0188695093efff5dedc7ba0672561c41c0f071666850f9e5d4c8ed90858460f349d08ccf574b7edf1d449f78df7ba553cf707e5253e253556303e9692f17772ad5b7a6f02e1ee2ad520d6bc3fa1807b5a6a444c7aabf1f28fa5e46bf897099f9e29d39e7bffd03c96ad10f65dc9378251b1be564b979f4f188c22b536898694dc2b64c15e35b0f93fdb25e32140e25bd9340ea046cc56ba7ea2cac12f87ade7d381cb0d992452b03f923b7341427a8b1fc36a3a6ed2876d85b714795bbfa0acf498e69041df6d3c33aa5f7d937994f1ad30a2ff438a8c78c185f5bf8c3ea90714a1d69c8688e6a2ee46d821b00cc26a94c81a2f053a8f94bf72e780b2773ad11d5399d0e44ff0f78bdae66cbbc8ce02c19b55ad3ffb97771a9677765ef576cd9958d9481ae57c91e5a4450427399d9c132f77cd429eacacaf7b57f1e4bfed54f40688a773d23cf9f8b09281789597560b4234f12140d1c136907c2e842c4aa2730499f485d6d409102f1423b05747646411959c520df3fdbf2f6fe2f023044c145624915f5085b6ca82fa223f4ac3d75752cbde57442584f5e09dbe07887c75e3f4d1b125dd43c8722d31ad07eec3efb0a5041e7d263ca12f6760aa6c0545fb1e6c01217791c16
#TRUST-RSA-SHA256 62cfc6857e4f4cf40b4cf4270c08cb7c08565b21cfe99f1e0c3a81f27033b78f0dbcbd0624014ba23eb54f04f08f18b044f56a9ce7cd31655df0da9a34d41dfc7581652a349cc552cb6f0a86339ccfd22da49a4b2d896b2d938c3fd281773e432e0ba97ab6d943f6902736d3df3c5c5e89b4ec2a5c8b210b11f415d1290f330739a8dfb6e328e7e5773a409503cf40c62964ac588deec85e24188e5295586d47e6ad6ca7b1eb6b1c90a4a18673c09fec5c003612da79c12b867c4241c70444b677e5a7d6c269584c73100d888641e44ff94d881b5d448844afa04d334024b602c2baa3745d7cd9e8ef380c2db4370a4c151dcdb32c133ff7c0db30504174fa420890a88e6d35eb838e1bf558262312e9f805561b38f2cfc1fda98a711d9549148f5d55bc58f4a180ec11ae58f39e19694306974c77ab8892715c3f6ab07a4c2cc511930c4b1a9d92b9a68b83b3b34bc0771ad4fef6e3e53c3e6ad56c587dae10ca64c2830cee43e901f6ca05dce13164109b0d3ddcb918347c29e5632ca90cbde88165bfab9a5f27fb0beac6130b15320c5de599cf4cc91c81d61c05dbaeb699c7b0ab08432614244d6e91c0de61b562a81a0f7c2a3abbbb9d799ee101336a7e5c4ed2ee76a8a0c451686896c2187e764c7492136e2ecdac6c9b19eeea80d8143b0906a0a8efd31ec5cb11826486801b53162bf419da166b26ace31458396c74
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141121);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2020-12820");
  script_xref(name:"IAVA", value:"2020-A-0440-S");

  script_name(english:"Fortinet FortiOS < 5.6.13 / 6.0 < 6.0.11 Buffer Overflow (FG-IR-20-083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 5.6.13, or 6.x prior to 6.0.11.

It is, therefore, affected by an buffer overflow in the FortiClient NAC daemon that could
allow a authenticated remote attacker to crash the FortiClient NAC daemon and theoritcally
execute remote code, although no successful proof of concepts currently exist for the RCE.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-20-083");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.13, 6.0.11, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12820");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");

  exit(0);
}

include('hostlevel_funcs.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  {'min_version': '0.0', 'fixed_version': '5.6.13' },
  {'min_version': '6.0', 'fixed_version': '6.0.11' }
];

workarounds = [
  {config_command:'full-configuration', config_value:'fortiheartbeat enable'},
  {config_command:'full-configuration', config_value:'endpoint-compliance enable'}
];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, workarounds:workarounds, not_equal:TRUE);
