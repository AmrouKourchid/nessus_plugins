#TRUSTED 3a991558d30eb7117b0893f6edfaf557933d610ec71ce65de311c57dc307812c9ea44b3407cf2d3e22b4eab538a937de9e4aba9b672dec0a22523b6bb35865e8fc97869f8937d2d80d80e3dfdb2bc010e61e8d5db5079b936db1fd1f8a57591f30c3c7a818d8b701d22244992c5ee98b4e5cb2bc5fc0a5483fbc431c5b2d744179f782ae2c4a7c7f9b0dac9d4815201fdad84172b31c7d82e7e9e758e277280570aa6d66e65aee10256c056548cc85a05860a318571f302ff0be920b8f7f59685f622fd06599fb9945293762bd6601fcafa720f1bc8f48dff7e9e56c3974e86ae5e2f0d953c282a01ff57c38755a5d2b5fb94669171004743e4cb20e281756673cef140dfd3e2b369214566e2396fa3272ef24498ef5fcb4273c58e19ba1d941a57ed8a97ed278164b746aaf5162923670c0c2631328d5c1496721d6af080841a3fb5fe0679d869b9084cb90d7d117ba9b1bb040e233fc80d95658047528c5c729d96b51597ba6297a7ddb40670fb8287081fac9ba7eb42654fbf62941171c0ddda49bdbb160287fd929b675372c94a204a4dbd7961c1ab238f0fc3da7207f6e675e1a2bb1d532bd98e2c011c95b6c50c686769dac6e95b072d0c3874175a0a1d35a1ebf495a30182978617ed82656b84903e3e4d2f40c5ac44e8dfbc4f1cf92da18e93f9824e115e8d612100f83aaaf1ff98776160aed87fa7138e56e28a140
#TRUST-RSA-SHA256 b1abc9ce96d5e5d3d6cf3513953db008b09f13b3974ea1073a6390355bcd664a207b882c003ec7d724fc3b04333d2071a9799917956f8a30dae75696d470dd55893b77936e2a5d28044dc56319931acdee1ff82164bea90869b87e1ad54a65691ba947179f6360c8ab4a0f676a849234d9bedb4618128be3f6d2319199f6f2d2659f9ae91c9191dfa91c3a947e42a32429e8526af5b87a74416cab7fdb3c278bc4584181ce4fe50101ea2af66023ef6a7fe619ae12589e410966f6da5886283664b5354ad6f46dfd8813eb6db3ee4f0894fb673f15f43f51e71dd09d82932fac0f39a130ae2a8c0c12f872a303f8eeebc4b93696600ca1ec72b15bde67c5341e30d1a7436dee3e1fa782665576104ae14ed33a4a456c8e6f7d9467cf2fe86b1cd0287dcac9dc8e925911981daea68f8142ec5a9669b5d08dd9e0e67d28300552abdc4d38be6155f6b388f68a260d539bf353a5fdef78a93c586c9e92081076bac970432900ddb455ee85dc5491812dd1287ac76ff9b75de57ef8d5eccc4b1f59fa38f5b0cda13e9215707e43f28404ac67981703d75c904051d5e1a5e3b0f2604b386b4236c4ca31f304008ea13f2681486b6065e462099b2e1573c1a7b6db2ee55776717e25cd534adbd6972ffbbef53229cea6fa8139183c206e29ce69ae1219e65472845bad4e58631fed69db2c2e1375db03c59537a29439decac17e0f71
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82569);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0646");
  script_bugtraq_id(73340);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum94811");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-tcpleak");

  script_name(english:"Cisco IOS XE Software TCP Memory Leak DoS (cisco-sa-20150325-tcpleak)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a memory leak issue in the
TCP input module when establishing a three-way handshake. An
unauthenticated, remote attacker can exploit this issue, via specially
crafted TCP packets, to consume memory resources, resulting in a
device reload and a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-tcpleak#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86ea2261");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCum94811");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150325-tcpleak.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCum94811";
fixed_ver = NULL;

if (
  ver =~ "^3.3.[0-2]XO$" ||
  ver =~ "^3.5.[0-3]E$"  ||
  ver =~ "^3.6.[01]E$"
)
  fixed_ver = "3.7.0E";

else if (
  ver =~ "^3.8.[0-2]S$"  ||
  ver =~ "^3.9.[0-2]S$"  ||
  ver =~ "^3.10.[0-4]S$" ||
  ver == "3.10.0S"       ||
  ver == "3.10.0aS"
)
  fixed_ver = "3.10.5S";

else if (
  ver =~ "^3.11.[0-4]S$" ||
  ver =~ "^3.12.[0-2]S$"
)
  fixed_ver = "3.12.3S";


if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);

override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;
  # TCP listening check
  # Example:
  # 03577CD8  ::.22                    *.*                    LISTEN
  # 03577318  *.22                     *.*                    LISTEN
  # 035455F8  ::.80                    *.*                    LISTEN
  # 03544C38  *.80                     *.*                    LISTEN
  buf = cisco_command_kb_item("Host/Cisco/Config/show_tcp_brief_all", "show tcp brief all");
  if (check_cisco_result(buf))
  {
    if ( preg(multiline:TRUE, pattern:"^\S+\s+\S+(\.\d+)\s+\S+\s+(LISTEN|ESTAB)", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  # TCP control-plane open-ports
  # tcp                        *:22                         *:0               SSH-Server   LISTEN
  # tcp                        *:22                         *:0               SSH-Server   LISTEN
  # tcp                        *:80                         *:0                HTTP CORE   LISTEN
  # tcp                        *:80                         *:0                HTTP CORE   LISTEN
  buf = cisco_command_kb_item("Host/Cisco/Config/show_control-plane_host_open-ports", "show control-plane host open-ports");
  if (check_cisco_result(buf))
  {
    if ( preg(multiline:TRUE, pattern:"^(\s)?+tcp\s+\S+\s+\S+\s+.*(LISTEN|ESTABLIS)", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because nothing is listening on TCP");

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
