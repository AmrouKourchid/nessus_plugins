#TRUSTED 602130fe24e3b66c188ae21c9b54a86c0dfbb5d826416bfd22956cf010e1d02e7d9df59d5b8d860c0927de1583e64cf1c385c6688a2d00f3f874bb032fc12a6f671dc4eac7bd9341dbdbcb9df093357bfb4bd68f383dd12a5e4e2b72ad6595383c1bbde60b3e50f8deb98b6c9cdb9e12364a4a301076c687cbe098eac461fa24a01eed5d1e2b054a6d59ee1889351ab35d36546b6cee26a2c8d082c7a89d961774476687e214873f88a46a08849ea485b23bebdc90216dae530aad44f6fb9ace877fff568aca592f9448a3edc31340e1c856edf8d709b5a8a33b34302a8df99be5a2042d2acc36ef771627b5701ea820ebef872c107bb6483494d2da8bd2685980fc2c6d2c1a71664da56d9ed9db5df44afab5b13ad124ff8f84055757c27bd8f71202b8407355bfaec15fe68675180fe47ab7fa50580df88193b09e3dd0c3d04446d0b430acd9f04af502e5b14957b1e1e5593d10932e5082c2a7673077345fdcc0554e63f7e2bf7e815a14ee1da94c4cc942c0cac59c071c5621dbe249832f0bdb81a445c06ac0a72dbf1980e48d1358476360b95fddbaee02756c1c64467f68187c5d8ac1b5462d67c03f98a208c398a52035adc38dd554bc9798055f7555e8e687f1cf09683c1442aeb70d28690823f65ea67a9104491d79c8f08c68559b16648882d56874d871ca996bca27fbf67fbbf97e2be0a5f67e564ebcc66dcba8
#TRUST-RSA-SHA256 5b69c17147ad1d010921ffaae331a77b1f22adf78ff9e600b7c15fb6a0934b48954af7a3a31b7b7c3edf3d97117a9645e407f555a6854927050a41c3fd51ff974ac609ed243d8b411058b9bd5fb13129b953db7a9eeb150e6c6d20766a00433fc7b0c046b9c9f063492b6aefc02a4d2fdcf249b66526215aa8cd189b97e3b9b2d089935864ebb826a2aaa6ef821b7fa86f50520797075798c59c62712321c50d59c2b861602779efa4388c132cd86eafae4eebdf40a28ff2210c223885626374c760425bc8bd5236bae63894d2ac4bb85ad8ece4c5897773f50fe77051767e87129ddeb4701f03202f9efe156fc74c35b61b541ff89af04d390f57cb91adc6dc16f15123a78d839023e8ca6cdea9b1e6eca7f969f7735f7fc610bebd02323ba954d3203f4853997a1b356b30cb66ecd5e95fe1c929a1cf9dd36f993e79bd385e904e72cc232a6d524002da6ccba6376703f9dce6c58f9f76f2c49d22a98b4cbab6003704ce0c16a370c3d749c7eee7e7fd1cea8420bd56c57cc70cba7b014d648207edd4cf1f8a9759b85b86cd87769b8a54ca534b0597526de2126f71fa53e9748b5a6b8ac3a0e84e9eef173a7c16f4703efd7fe6ba37f9e89102ac526ad6b1215c03b72dc8804a91d94b27d46922b1117731534a37abedc8321dd97e706faf5a357d44dcad1adb58cf17d6cc86c241fa8948e5adf8437bb758c25c8e15a6fe
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133863);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/26");

  script_cve_id("CVE-2020-1602", "CVE-2020-1605", "CVE-2020-1609");
  script_xref(name:"JSA", value:"JSA10981");

  script_name(english:"Junos OS Multiple vulnerabilities (JSA10981)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by 
multiple vulnerabilities:
    - When a device using Juniper Network's Dynamic Host Configuration Protocol Daemon (JDHCPD)
      process on Junos OS or Junos OS Evolved which is configured in relay mode it vulnerable to
      an attacker sending crafted IPv4 packets who may remotely take over the code execution of
      the JDHDCP process. (CVE-2020-1602)

    - When a device using Juniper Network's Dynamic Host Configuration Protocol Daemon (JDHCPD)
      process on Junos OS or Junos OS Evolved which is configured in relay mode it vulnerable to
      an attacker sending crafted IPv4 packets who may then arbitrarily execute commands as root
      on the target device. This issue affects IPv4 JDHCPD services. (CVE-2020-1605)

    - When a device using Juniper Network's Dynamic Host Configuration Protocol Daemon (JDHCPD)
      process on Junos OS or Junos OS Evolved which is configured in relay mode it vulnerable to
      an attacker sending crafted IPv6 packets who may then arbitrarily execute commands as root
      on the target device. This issue affects IPv6 JDHCPD services. (CVE-2020-1609)

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10981");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10981.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1609");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('misc_func.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();

fixes['15.1R'] = '15.1R7-S6';
fixes['15.1X49'] = '15.1X49-D200';
fixes['15.1X53'] = '15.1X53-D592';
fixes['16.1'] = '16.1R7-S6';
fixes['16.2'] = '16.2R2-S11';
fixes['17.1'] = '17.1R2-S11';
fixes['17.2'] = '17.2R2-S8';
fixes['17.3'] = '17.3R3-S6';
fixes['17.4'] = '17.4R2-S7';
fixes['18.1'] = '18.1R3-S8';
fixes['18.2'] = '18.2R3-S2';
fixes['18.2X75'] = '18.2X75-D60';
fixes['18.3'] = '18.3R1-S6';
fixes['18.4'] = '18.4R1-S5';
fixes['19.1'] = '19.1R1-S3';
fixes['19.2'] = '19.2R1-S3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);


# If forwarding-options dhcp-relay, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set forwarding-options dhcp-relay";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);