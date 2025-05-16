#TRUSTED 685aa49afa2ee2aebb01d119ac09d51a75bfaca0bccc0bb7809d466982b535c0627d4b80b22f39feb11e6173283dfcf20fc9553e09a2af751a9a0b6b5728eab07e3f12f213718fb84dbaeee943e7549759ec3a978af7c6335e6cce989b2b90d73cd1fda4d772076cf5a0e664c65a8109b34ce31c199924fdee76d89d377461cef05b0be5705c349f08c497cf3879242b9158e220f47367820f9cb74fa0c806ae25a7498bd3b32b30d74aa286f2525cde93ffcda885997099390b053ce1c5d96f095474ae4cad2f748611a76ddc94d1943f8e5ce1f8909ef4319e48332a3f6b5a7735d41add8ba1c0049ea56ff8771881f1971b1365c59198a7ca7d64de91b2684a8afd371eeeaef1f6af197fdcb0bd2e2e94947034c37ec7c17009aa502cfeeb335636524aa55f018c3b9549429a6c6b1c5c00922f74275c1dabed096c54eff590cd87595fc7acf80fd5e1f878d381d30271db9175843e4de3115cc51b28bb188cd58482d990b45d008abf4308d4730594ba5c1eaf5941953282aaf00b121004c827aa24271184484cd489c4e8610abdd89f4f83b5ab8d93a03068dba9880e039b4998510dfdef87269789977289dde22ecce30a6aad641fcf9024f7e499b2a3c78d4467c956b8c7365254bd36f3d4fa556208d67e6b77f28785bfb6bf5d2652dc5131676267f27feeb163dc493d9244e94c6c38b62be4a03f86942fe615ec41
#TRUST-RSA-SHA256 0f52b485ee905091123457f3f52a9aea035dab9d4dcc4f65642a5d354ec0ff754bbcccc2841eee7c0dccd12cc323ee8356c2e922ddea8f15ac1e873d0fd8e57a83e240e2b17d5425596a6a18df7982525c27dc7676598ecbe1b0348fd9dd066e119ea0e141a2159f65621db8f0ad947a38ffb5606a497372e8d7f297bf2675b7b106ca9984bdbadf7b2b5547365f63a866b20d856f9cc0bdeb7b246eb37c554cada71b3134c9be8af2f0a8623436ba7cab96a383d251fefde79c3981c88034ceee001c9642af89a71b7695a151adfd1bff7810a7dac842b2de68fd43a9165b0baa025d4010e4aacbfcf6f15c684c198b8b8fe42763b844fb08857586b00517f24836826da0550d190f975d702e786475c67970915ade11c6bcbaee716629e66bec73a0aa61910ebfc46989698cfa4c53e3b5b0d8bae673630c9cc7323d5bc9ffd92e4c707d11804353a3a608fd9e87149c4def0ec75a33a505d01878ddf20a3c9b4622c8420ed56ce1c1377075a482e2e64b984d516d84d333ca0b614f8427a47a5c1ba61f2eade86d5344d74cd6374c3872200073c2c1378743d3dd342acb06cce7a1afe1e26d355895d7785503aff285285037b91ece3eca9c35a6aaf8feb7c869d5aa251409f3b1bb59412e9bcc8116e59561087651154921a38a0e177b57d4fd30c559afaab120dedbe41cba60d56bbb9c8b192e06e4419ffb138c599145
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70731);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2013-3834");
  script_bugtraq_id(63138);

  script_name(english:"Oracle Secure Global Desktop ttaauxserv Remote Denial of Service (credentialed check)");
  script_summary(english:"Checks if patch is installed");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by a denial
of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Oracle Secure Global Desktop
installed that has an unspecified denial of service vulnerability in
the ttaauxserv binary that may be triggered by a remote attacker."
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(
    attribute:"solution",
    value:
"Install the patched binary per the instructions in the vendor's
advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

  script_dependencies("oracle_secure_global_desktop_installed.nbin");
  script_require_keys("Host/Oracle_Secure_Global_Desktop/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


enable_ssh_wrappers();

version = get_kb_item_or_exit("Host/Oracle_Secure_Global_Desktop/Version");
if (version != "5.00.907") audit(AUDIT_INST_VER_NOT_VULN, version);

# this check is for Oracle Secure Global Desktop packages built for Linux platform
uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

if (islocalhost())
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}

cmd = "dd if=/opt/tarantella/bin/bin/ttaauxserv bs=10000 count=359 | md5sum";
cmd1 = "dd if=/opt/tarantella/bin/bin/ttaauxserv bs=10000 skip=360 | md5sum";

res = info_send_cmd(cmd:cmd);
if (strlen(res) == 0)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, 'No results returned from "' + cmd + '" command ran on remote host.');
}

if (res !~ "^[0-9a-f]{32}([ ]|$)")
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, 'Unexpected output from "' + cmd + '"');
}

res1 = info_send_cmd(cmd:cmd1);
if (info_t == INFO_SSH) ssh_close_connection();

if (strlen(res1) == 0) exit(0, 'No results returned from "' + cmd1 + '" command ran on remote host.');
if (res1 !~ "^[0-9a-f]{32}([ ]|$)") exit(0, 'Unexpected output from "' + cmd1 + '"');

if (
  "e8490e71847949c9cd161db9f9eece95" >!< res ||
   "bfcc1282a99455ffeab15a348a1cf3f8" >!< res1
) audit(AUDIT_INST_VER_NOT_VULN, "Oracle Secure Global Desktop");

if (report_verbosity > 0)
{
  report = '\n  Version          : ' + version +
           '\n  Unpatched binary : /opt/tarantella/bin/bin/ttaauxserv\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
