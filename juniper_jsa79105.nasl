#TRUSTED 676be910ba23f0f128614833d5d7e8c3bb0d961d88c45e8c2c93583db88212d2b1c94c14f2fd4cfc862664e714c8db3726599800e7de1d07fbff5f4b4ff18b8154838b6223c7549a1b08dfde233a40876064f9c7977e851eb85d5144a7fe18866f1d1901aa792f6d773c8180e28de159a72459dbe672b6884a2d2e8c4bb6349baf60d5eefcbb932e0c99c42c8df4da6afbb7bb1096afcdce5b0f41ac532ae24e3175d340cf0541a87f645e5e2b2d3154ade605f8dab35e8a87859dd860c57c35d8273a25173a06db5935840a7dd69059f9aa6ea3cacbe5f821c224a276a036ff0b37bcc3524082e9a87e0a51ef517b560c45d9528d0dea13a5012d0cd48848a1dcf4c47634051e7aa6eca9b4f39ea5791413ebd6fc7df9094cde2842d4eaa5ba442d1808559b9ebc23bb2e376b9d5e72a5c7452e814fb636170f2e11a5c4d6378eaff4152460541a036fb79e1cd1c34ec483e694bdd8aac2e603a465287bc58a8adb8fbaaed3834cca5c89c85de0824b03088c01722a68787dd93ee043ed22c14af756d64151a527c189e887d7f2fa749e0492a611503ce2adec64ab35055f9d5f654d13ac42c507004aa80a9b5e448560b6afc4afcb78db6c6fcd45729f9db7ce135669363d50520aa2eb89c96b123d8f734e04bf3b7e76ddf5ce377076c93da44adb86e30df6e79ca9fd21403402a5a853b7e1b51b0ddcca308603aba0278d
#TRUST-RSA-SHA256 a1649d72e4a23b441e76dc6e7d0c79773b1c2aecac1cca29538bab78a6615101e93e3691af9d0e7f897257dd1e54def289c11209cd0d815fd00d96b3c2fe7b36f39ae18ba090412781a06721459eb9470cae21980f1e78d6ccaa4b47b9c65708c85da72e18dba7dc372eeac4aadf08e0217fe7162c80a832d56be8c5a62cc044977d5a0160a9cf282736fccd18c6c1f3ae881e4ac30bb28cf27c7f8c2516dd49816cc72934ab077bfb160702574d2cd6a070be342ceda8d201f470ee2ed80ab89374b4bd32c85f1a998b918d48fa219507b5822ba51166c28a924333622c277ce704fe46f99808a1f35746735d8445e521c29ed4f6fad3ac84861c2ef291142aeabaedcd158b1523db179217fbd43f0ec5275e534b17ce6d8fe9a9299bd6237671b3803a419dc0a74de8d34f91759432e6aab770b1fe95f9d20c1509488b095751ce9dc7d2387b1ffab38e09efc99b84297663011d8c425259bfd08690d056c6071f782549bacec5e8be507822adf4bf8d0f918ed1ad13f45dac76939f62b94ed23d32b768094cf6cc1308ee4febbf316ed1e4ddb2cd3a060cc007bd5a7c7898670bf21eee0f4fd4c9d9a9251f2e30f95bd49d32105a6a1dbb3e99bfbc78cfcfedc06186cbb43af816796d7874c06152bcde2a0adfbb9ef503904006b5f4e93ca1acb61310bbf525f76e33abf577b09cb7a98214968449fb1c26ad8308a39261
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193873);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/25");

  script_cve_id("CVE-2024-30405");
  script_xref(name:"JSA", value:"JSA79105");
  script_xref(name:"IAVA", value:"2024-A-0232");

  script_name(english:"Juniper Junos OS Vulnerability (JSA79105)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA79105
advisory.

  - An Incorrect Calculation of Buffer Size vulnerability in Juniper Networks Junos OS SRX 5000 Series devices
    using SPC2 line cards while ALGs are enabled allows an attacker sending specific crafted packets to cause
    a transit traffic Denial of Service (DoS). (CVE-2024-30405)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process?r=40&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f52ed971");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed?r=40&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f121aca9");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories?r=40&ui-knowledge-components-aura-actions.KnowledgeArticleVersionCreateDraftFromOnlineAction.createDraftFromOnlineArticle=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a73cfa7d");
  # https://supportportal.juniper.net/s/article/2024-04-Security-Bulletin-Junos-OS-SRX-5000-Series-with-SPC2-Processing-of-specific-crafted-packets-when-ALG-is-enabled-causes-a-transit-traffic-Denial-of-Service-CVE-2024-30405
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53cf014f");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA79105");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30405");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "SRX" && model !~ "(5[0-9]{3}$)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'21.2R3-S7', 'model':'^(5000|SRX)'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S6', 'model':'^(5000|SRX)'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S5', 'model':'^(5000|SRX)'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S3', 'model':'^(5000|SRX)'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R3-S2', 'model':'^(5000|SRX)'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R3', 'model':'^(5000|SRX)'},
  {'min_ver':'23.2', 'fixed_ver':'23.2R2', 'model':'^(5000|SRX)'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show security alg status');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^SIP.*:\s*Enabled", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) 
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
