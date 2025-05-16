#TRUSTED 304a2cb803164f2f15b56ce7a51e6d25ebba2d12568f07bb1e953ffe678ff4f575ce59eddca7658cb3aeb0cd86cf0e70bbc8d7fc00c2b69ee214381e70ebe24ee50c182f259593faa9b5617aae76e9544456bbe601dba2640b22654894f0e0854d95a7214b67dd4a5d047be0a7f96ad3aa86555547e888e4cba4616acc285b6b8fcfa76ad3215d6a2335e9742c9dcce1de825632abd1da8b044971ed32daa2e16653a099adfd582608f8ccf4193795e251d08988b9baba1dbc908300e2e578496e1031eb3dc0330ae8e2f7ef76de35f31d36dbcbd51eec5d8284b24ff61dede9f02d8a25be64f3a67de1aa04d4f87746b95b300b6ff25e2ad59da8ae340c3ae64430085a71136740ed643df3fd91f673acbc1d28c53a8566cb937e1dd106980db9366d64fe7a37ef7c0b431f9f9f471badf2c035b6a7b5033b60a7b55ccbcd2ea19890bcecbd0ffffee7e2e35877dee5beaeadea62256099831e20a5391bf8526f3dcf09a1f4ea3d3f66818b27759e3af9b3081d2bbbd6f4b45ec7a51256b3b4bb3ac633b3dceb0749ea241f837cd1dd72a2e0636e83b00670ad7c4df00d9d9af8dd91e896de28843b0bfce4858e534ceced7c1e9e1cfa5c37b1709c16d65da0e01c66d319f843642b79da128a43154c7043ab6215712f6d96c0b3bd568a4dbced388ca8b96a9e6115adb5b6f86a38b8b33c735b4be91ced2f800e8462c8f9a5
#TRUST-RSA-SHA256 a0a047f75a2c1802928b245df776e6930fa7eb5c5a6c3af0661a7177f6f0f4121bccda7d6238e334dc6965ffe020d4ce25ad54265514659a10a52e89fcbb8681bf27d0bb68e2e94a8e9856360b8d6ad607ae635b5aa231ebaa7c749c6aeec4e32ae00277a892c46dd2cf0ecffef7195033ab8143fd257c66a59a5ee7083e3ac05df1dc4c5035ea1f338f341a91d823d72ac486de0820fb4473b554381e7c9340e9e8fc291159f0c3dd0c6083f7ea9f3718082da20f0645a01f48e0f86668667571a9aaeccd42ecc949c69f2a77a5bc52388b68132b46c9bcc7269698edba7041424157c45db7bc2c4c6e3962dda5a971503699fc51b4cf83b416fd5bc620c6d63ae6a0035f0eb8f9c9947d161f84032377ecd00ad06a4411bff8f50092f70b4ab8d9132bd58e9ef46cc38b4c630aac1060b5693dc9481f2fad255bf44ebac044f936d0508a33ff97074f0837339f4c68a7dadeb4ed8b6e6ef2b502abf86ac7ba4a7c6963bcb0bee11923f5a4c33ca144a0971f0544793bdbda12682b17dc0ca9418a0ea7b461d4462d4b1bafab184a0462369cc86f815c048b79b874d80a07197b5c8616e136f8fcff443f684685e75c094dd2ba81a9d4746ac79d7b4a0d6449b2254a165cf5f0103f26cfaffab12d0fa03c44b888d3a21aca2f4c55bff2e3d8e64616db3436fb89de00c2b3f24c440d3801a6441cb64e8ac69b8831b18d9a30
#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(193143);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/10");

  script_name(english:"Linux Time Zone Information");
  script_summary(english:"Report time zone information for a Linux target");

  script_set_attribute(attribute:"synopsis", value:
  "Nessus was able to collect and report time zone information from the remote host.");
  script_set_attribute(attribute:"description", value:
  "Nessus was able to collect time zone information from the remote
  Linux host.");

  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_ports("Host/Timezone/date", "Host/Timezone/timedatectl", "Host/Timezone/TZ",
                       "Host/Timezone/etc_timezone", "Host/Timezone/etc_localtime");

  exit(0);
}


# Not all Linux OSes will have "Linux" in the uname in the kb, but that doesn't mean we weren't able
# to gather Timezone information. So instead of checking the kb's uname value, we check if we had 
# any success with timezone commands

if (empty_or_null(get_kb_list('Host/Timezone/*')))
  audit(AUDIT_KB_MISSING, 'Host/Timezone/*');

var report = "";

var date_result = get_kb_item('Host/Timezone/date');

if (!empty_or_null(date_result))
  report += 'Via date: '+date_result+'\n';

var timedatectl_result = get_kb_item('Host/Timezone/timedatectl');

if (!empty_or_null(timedatectl_result))
  report += 'Via timedatectl: '+timedatectl_result+'\n';

var TZ_result = get_kb_item('Host/Timezone/TZ');

if (!empty_or_null(TZ_result))
  report += 'Via $TZ: '+TZ_result+'\n';

var etc_timezone_result = get_kb_item('Host/Timezone/etc_timezone');

if (!empty_or_null(etc_timezone_result))
  report += 'Via /etc/timezone: '+etc_timezone_result+'\n';

var etc_localtime_result = get_kb_item('Host/Timezone/etc_localtime');

if (!empty_or_null(etc_localtime_result))
  report += 'Via /etc/localtime: '+etc_localtime_result+'\n';


dbg::detailed_log(lvl:3, src:'Linux Time Zone Information', msg:'Timezone Results:',
  msg_details:{
    'Report':{'lvl':3, 'value':report}
  });


if (empty_or_null(report))
  audit(AUDIT_NOT_DETECT, 'Linux Timezone Information');

security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);

