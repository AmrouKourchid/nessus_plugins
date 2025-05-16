#TRUSTED 618f8c39d186b571abc0d72d1df53f02babcfaa95336c16077a9fdb85cadafb46e6634902de057cac728b9f1148528eaf6961f8433629fff833dc80dbbabae92bd803aeedc4d54a198b68dc90b1c092153f98016675b7709c13d07fd70338e991f98e0e92a1d871298134d8a9dbe9fc10f454c662b0de13167644e263cbd9ee0c4c86c75c8ef5ed26e455bafbc979d3852dc234d74363e9595445c952d0b4182d54095047fa716ad75870d395104e70ac75f7a4268da9b8a2b534dea0c5fa2138f2ed7d71ecb1fbd6a63fb2dd35bf523c9182515469d22238ebaef03dd6bfaaad6b0366380501d1c002559ecdaaaa1797cb2375f7a6920742ad017a92c9e9a1eab77ec3981865b54ccc3b46c8b0ce7fd585d4c89c934276a2513ff48514f5705fc1389b6f49a59a06f3bd0c739d5a9e12990fe410a86baf36a6f978e071b091d16ec335dc8a96878cecccf1dc5bc9e32f5a6b2ba964baa9e601b7a12f423a2edadef29fdf9007083c7b45fc1b855df0724e73016f37d31834247e5cf44e4fedd414f79a34db08b4406288e3f1f42fbd1f1d7fb14b5322e17aa3cad25f11a1b0ec8a8d8652eead2c194397feaae2ba19160e0e61df4fd36ff2a8de28cc09f8b3419b54b432a83bd6976d5466fd617b2210c69ba6d7eecc11390a94b6ad333621aab1e86a517b3fa60f9fc1d0125acd478e71326e1ce3a10744f9fd0fce94d7161
#TRUST-RSA-SHA256 7fdb88feaaf0ed9ec31254879ce12c0f78184cd0c4b2c1a2f1111a27afa653c2a83b78b266efb9b5e7c8e5ff9dae9dfbafc84032851f7fd4692081c33939ec46c36623ad7c3dc33732e864d56ea538335746f9cf83277c78109bee6fe32a953f7d85172c671d8552b22a9d2002b2c4c23911dc38a9d405907126f0e81ffd21d6880e3eb1589469100aa62bbc557402d128f10dec95c29c7c90c0e7f3d5cfbd8a5b2077228fe3a11cb42fd66778a4fe227cb2508fddc81cb15cd59854fb55b60179b4782da6fe78e3a5d5fec109a42fee8137dde5f11b799bd4167ad466e412cd467153ea22793aa8dc087e388b2b757fab0e72dbd3d1ef8381eeaa900c42fc4dd332a5db5bbbf9629cd3d4c296c4da55d49324e7885f0a2b6fbd742c8bf4ec2b2f3095fc280a840dabf88c028dd2b41c383de5ffcc41bee37d68c83b3d4b5807a43c7cbb5ab40fe1db2cc4ff3b4993c5e5cdc4a638630bc76768e3560d307c42666d07d55d54769009dfa43beaa10eccc62d57484f5be3e6ac853b53c39c32b332972f94473c1b4a8be32bc7dce7e060ad333e47a03c3221ab32cb1c6c42ba2d31fe524807192a4027e4c08f197d165cf0256fac25d119e6b372023f64b38a4e252aeafdbed80a4fd7412f76bb34b19e53b614adb2646a3d1e34b07de8f8b209448250f9a9a635fef768aec5d1c1efe7811559326aa7fbe083550a95da96face
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133050);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/29");

  script_cve_id("CVE-2020-1606");
  script_xref(name:"JSA", value:"JSA10985");
  script_xref(name:"IAVA", value:"2020-A-0083");

  script_name(english:"Junos OS: Path traversal vulnerability in J-Web (JSA10985)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, a path traversal vulnerability in the Juniper Networks
Junos OS device may allow an authenticated J-web user to read files with 'world' readable permission and
delete files with 'world' writeable permission.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10985");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10985.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

#15.1X49 versions prior to 15.1X49-D180 on SRX Series;
#12.3X48 versions prior to 12.3X48-D85 on SRX Series;

if (model =~ '^SRX')
  fixes['12.3X48'] = '12.3X48-D85';
  fixes['15.1X49'] = '15.1X49-D180';

#15.1X53 versions prior to 15.1X53-D238 on QFX5200/QFX5110 Series;

if (model =~ '^QFX5200' || model =~ '^QFX5110' )
  fixes['15.1X53'] = '15.1X53-D238';

#16.1 versions prior to 16.1R4-S13, 16.1R7-S5;
#17.2 versions prior to 17.2R1-S9, 17.2R3-S2;
#17.3 versions prior to 17.3R2-S5, 17.3R3-S5;
#17.4 versions prior to 17.4R2-S9, 17.4R3;
#18.3 versions prior to 18.3R2-S3, 18.3R3;
#18.3 versions prior to 18.3R2-S3, 18.3R3;

if (ver =~ "^16\.1R4")
  fixes['16.1'] = '16.1R4-S13';
else
  fixes['16.1'] = '16.1R7-S5';

if (ver =~ "^17\.2R1")
  fixes['17.2'] = '17.2R1-S9';
else
  fixes['17.2'] = '17.2R3-S2';

if (ver =~ "^17\.3R2")
  fixes['17.3'] = '17.3R2-S5';
else
  fixes['17.3'] = '17.3R3-S5';

if (ver =~ "^17\.4R2")
  fixes['17.4'] = '17.4R2-S9';
else
  fixes['17.4'] = '17.4R3';

if (ver =~ "^18\.3R2")
  fixes['18.3'] = '18.3R2-S3';
else
  fixes['18.3'] = '18.3R3';

if (ver =~ "^19\.1R1")
  fixes['19.1'] = '19.1R1-S4';
else
  fixes['19.1'] = '19.1R2';

fixes['12.3'] = '12.3R12-S13';
fixes['14.1X53'] = '14.1X53-D51';
fixes['15.1'] = '15.1R7-S5';
fixes['15.1F6'] = '15.1F6-S13';
fixes['16.2'] = '16.2R2-S10';
fixes['17.1'] = '17.1R3-S1';
fixes['18.1'] = '18.1R3-S8';
fixes['18.2'] = '18.2R3';
fixes['18.4'] = '18.4R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;

buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set system services web-management http(s)?";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as J-Web is not enabled');
}

junos_report(model:model, ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);