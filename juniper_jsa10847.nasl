#TRUSTED 6b0f6de78de368e573febf473fc12edfb3e5cc1d61f8321cfcd8839eceffdce08db4e4b0f03d2d206d58d4b84c3c0eef002c79f6722347124d1a3bd45671d3332d0edccb55d9680ffe6d99c01bd9b8a5e20a576aa877b92cdcb9d011c2ae0354895e294c44e36202b5293e8e2f1a788f404fab4594f0617869377c1fa63d35b111b855fa69a35adb77e053093b30e3345b39ff569209b6ef9359c16f38846212544d2a617ed275fc25aca1f66bd6ad114febcf67361a3529464b7dda159f177b6c01a8d1447f9b6d543d10fe78bd1f13f75506f22ee067f904b7931900b738cb74ea92126153dcb75f4f6ed013fcc77300b477ed1e9c2b0732d677d974a347af539d0070542df8324d9dfe27293cb46a32afefde7322edf58f667f0f49d83467fe1eef0f59823627be7b5af796c57722f64964e15075b9b4789d7762cefb86120718c4f746475d7eda64d543639df84bc5b4ee6a00af0428d619241ac20f9ec43aadb237a22aaf1ca11d2e0c5a29f3395f4288113cfabba1a473d5606c4f549478875304aa86575cf75410a69bf5ced876f1cd09e3035264515bbeae4749651f4b9fc42988095fbb6ea5c907965e9825592a0989b5e9df002f54e1d1c6ccbcc2ecdfddec8b8905bd24f7ea2f9383f104173d46d9d2648bf9b0cffde2896a65c289b4fbcda6bdd3b017fa486a1dae868b61799222443b27c0872b78f1aa0d6d61
#TRUST-RSA-SHA256 08eb64e1ca975151ebff09b96789038211c0c2b0aa55ccf7babcdd232fbe4847199ad188ea840f93d761f9e434fad39c50ffa43428d1531a6d57e37a73bdd9d478d0af0732d7a83feb9bcb5c0194aa4e241975b310086c8ea7a336b819e252b536389a06a35a7e67a557810b81871a6ae3d92d5a07ea27f034be15d5c005259a22a9d8a11cc12ca2a5d87158f65417b87352c782002754ec20567cf254066214b1701a1914da749f85e0590af32b6ede539892fc3a6f02a3d1bcbeb87747df7543bc46c6f55c3568bfbbf1b9ffefa2f05e5acd61f4ec672bf0d8e843b0daeb4fefef6cf134687d8665ef79f8af61792f2b46edac3f87bbf8c5e22113a1bd9bfc073dac37bf7a39b29c982f60301a5568290b48122b1f2112e49f8a736b0752d50d2a7cc822d60152c4f5f9790d951149836e5f56ac042aa546746bf9c5dc3b122f9df44846ae66e1218cac71a1bd8c50a49481edc6d98da6366b97b52916e55fcbfabd03ac44beb85475babb1e02bc55ddc3a9a50727f8803517b7c5f6a0ce9ea31556d3a469f2d058f4653ca1fb29bf3f789f7c5c53f669f8f67f5f999abd4f37773511a3e8292064aa52e4225bbe97422c1d9ba13f54b3ccd89464abe59b93e5a0573e54bc9843cca25123432aab1af52747384f5fe6a36e6ddf38933a06e652a7130296868c469a896c79f744abc444d1266bda1c268234881494dd66cc57
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109213);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2018-0019");
  script_xref(name:"JSA", value:"JSA10847");

  script_name(english:"Juniper Junos SNMP MIB-II Subagent Daemon (mib2d) Unspecified Remote DoS (JSA10847)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by an unspecified flaw in the
SNMP MIB-II subagent daemon, mib2d, that allows a remote attacker to
cause the daemon to crash, resulting in a denial of service for the
SNMP subsystem. No further details have been provided.

Note: This issue only affects systems with SNMP mib2d enabled.
SNMP is disabled by default on devices running Junos OS.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10847&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6679acff");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10847. Alternatively, as a workaround, disable
the SNMP service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0019");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();

# 12.1X46 versions prior to 12.1X46-D76
# 12.3 versions prior to 12.3R12-S7, 12.3R13
# 12.3X48 versions prior to 12.3X48-D65
# 14.1 versions prior to 14.1R9
# 14.1X53 versions prior to 14.1X53-D130
# 15.1 versions prior to 15.1F2-S20, 15.1F6-S10, 15.1R7
# 15.1X49 versions prior to 15.1X49-D130
# 15.1X53 versions prior to 15.1X53-D233, 15.1X53-D471, 15.1X53-D472, 15.1X53-D58, 15.1X53-D66
# 16.1 versions prior to 16.1R5-S3, 16.1R7
# 16.1X65 versions prior to 16.1X65-D47
# 16.1X70 versions prior to 16.1X70-D10
# 16.2 versions prior to 16.2R1-S6, 16.2R2-S5, 16.2R3
# 17.1 versions prior to 17.1R2-S6, 17.1R3

fixes['12.1X46']  = '12.1X46-D76';
fixes['12.3']     = '12.3R12-S7'; # or 12.3R13
fixes['12.3X48']  = '12.3X48-D65';
fixes['14.1']     = '14.1R9';
fixes['14.1X53']  = '14.1X53-D130';

if (ver =~ "^15\.1F2($|[^0-9])")        fixes['15.1F'] = '15.1F2-S20';
else if (ver =~ "^15\.1F6($|[^0-9])")   fixes['15.1F'] = '15.1F6-S10';
else                                    fixes['15.1'] = '15.1R7';

fixes['15.1X49']  = '15.1X49-D130';
fixes['15.1X53']  = '15.1X53-D58'; # or D66, D471, D472

if (ver =~ "^16\.1R5($|[^0-9])")        fixes['16.1R'] = '16.1R5-S3';
else                                    fixes['16.1R'] = '16.1R7';

fixes['16.1X65']  = '16.1X65-D47';
fixes['16.1X70']  = '16.1X70-D10';

if (ver =~ "^16.2R1($|[^0-9])")         fixes['16.2R'] = '16.2R1-S6';
else if (ver =~ "^16\.2R2($|[^0-9])")   fixes['16.2R'] = '16.2R2-S5';
else                                    fixes['16.2R'] = '16.2R3';

if (ver =~ "^17\.1R2($|[^0-9])")        fixes['17.1R'] = '17.1R2-S6';
else                                    fixes['17.1R'] = '17.1R3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If snmp isn't enabled in some form, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  override = FALSE;
  pattern = "^set snmp";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have SNMP enabled.');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
