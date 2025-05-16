#TRUSTED 79fb548cadb8ff92d8c87731a1e6203d730fe0833ec47b59c758b08d49e5b77a56ede9fe43fe5a055ecbe5f2a51132d00368d43cf2b2e60abdf4c251aaa845962c5a214e71d0bb0fd7bb4c8dd4a57625b5069eaaf8eb058c1520dd99d30fbd09c4c7222ccfffc634d7aabc74f81351d7e518f9176532b47ba21479a9982cf72fb6e26756c40d992173be3db9c613cc4b84880f4fbc84ff9d3b3f997099de583f178cac1ada40ec1a12f98259bd56d7ac017ff7d6da7b7dd2bcc6c94606db8b0e5b99ea4089d9912f52c43f08a40ad7d851359cf2d35e50f8378c0c05e151d89291d6b70b63b00d19d36901dcb6561b61a75824a0a24b75bf77b7c08e7204ff2779baec0ceadb4057b9022495bfbf1fc00783a856fdc2f29706bcca52b44776d0b7cc01188453302a8f6a1fe7a93d738dd7783d04172ff89874bb9d8ccc10d0b1dd95dd2d99216a5a3689686a8fc702626e6d2450061444859c88b58689c15c0d9caa0da145c218b064f832934569bdd2c7709916665c12b125f32205bd8ec901a676ba60f0c967072c6706931c97776b2040675e1315d01030a8bebf0475588cc2bc914b566f0c1d398fbebedab176e8482c119b96b705ed7e8d3ba922f4b168c4efa4f656b65bc7cdb12e32707a1c52b906ea0a652ed1460ce3a96067527887e99897d4588ee217afc7bd95547d825cc486f8b4fa20fd313d4e4c1187b2d871
#TRUST-RSA-SHA256 125ebb70a2a4ddfe6f6f1456ece0eb05bdc5cb919d7ae9edb8beea8629bc1ad8f267b8f23ddb8dfe997feebc08d961b32d1c672f9846ae6501739b21fb4af631a8de1505a5fa899b978cb8814d3776a273b5e2b4d9db842ae435b360a202f0d9f5491788e0e7d5e95a4e12962eac9fb3b8fbc413aab982c851aea7a1d9307e38de170c2a6f88fcf2f2d6b0b430c5e1d82a5a3cb12b9348d3a9344215baa689ad225188e5c0020b86b7b388572bedca2331af515d7fc1b5ddd31bdb2f7298665f7a8ffa2ce8c6620f4fb8cbb9b65f41685a492eb91ceabc6046474fec4034340e61eb806cecdd28eb648987effa30b3c11f8997342d2cb8f4c5544f6e03dcd6f4606040d7fcea97d2859255446372145b15f6e1ef8820dbdefa2c79021fa2952093eb1367311096e60eeec8a877fe3c4ea7ff6f4393aa884526dc4d7cbbed8f844a8594986f708ecb07d91f8ef43181691bf527f1bf1f27698d81b5067b27dc2609ad2f3392085ce59c98e8d1345aee2381b71bf2ed4ddba31ad809f04ce7cadf8469b94da6331b07b9d2bd075f6993c36d4515915e4721d20af066e4b3a9c1ea1102bfacf5cef204c15a9de80a30604cd7077543bc6feb9469df94b5267d5af414e5d546f68d10f237783716674399100a5d98f03089c86a195d7f9b7f315946b116c320f8e39383b5177fbea35b3075468998c48022f54a345d1c57a6d44ace
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(32320);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2008-0166");
  script_bugtraq_id(29179);
  script_xref(name:"CERT", value:"925211");
  script_xref(name:"EDB-ID", value:"5720");

  script_name(english:"Weak Debian OpenSSH Keys in ~/.ssh/authorized_keys");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH host is set up to accept authentication with weak
Debian SSH keys.");
  script_set_attribute(attribute:"description", value:
"The remote host has one or more ~/.ssh/authorized_keys files
containing weak SSH public keys generated on a Debian or Ubuntu
system.

The problem is due to a Debian packager removing nearly all sources of
entropy in the remote version of OpenSSL.

This problem does not only affect Debian since any user uploading a
weak SSH key into the ~/.ssh/authorized_keys file will compromise the
security of the remote system.

An attacker could try a brute-force attack against the remote host and
logon using these weak keys.");
  script_set_attribute(attribute:"solution", value:
"Remove all the offending entries from ~/.ssh/authorized_keys.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0166");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2008-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("audit.inc");


enable_ssh_wrappers();

get_kb_item_or_exit("Host/local_checks_enabled");

uname = get_kb_item("Host/uname");
if (empty_or_null(uname))
    audit(AUDIT_KB_MISSING, "Host/uname");
else if ("Linux" >!< uname)
    audit(AUDIT_OS_NOT, "Linux");

SSH_RSA = 0;
SSH_DSS = 1;

function file_read_dword(fd)
{
  local_var dword;

  dword = file_read(fp:fd, length:4);
  dword = getdword(blob:dword, pos:0);

  return dword;
}

function find_hash_list(type, first, second)
{
  local_var list, fd, i, j, main_index, sec_index, c, offset, length, len, pos, file, tmp_list;

  if (type == SSH_RSA)
    file = "blacklist_rsa.inc";
  else if (type == SSH_DSS)
    file = "blacklist_dss.inc";

  if ( ! file_stat(file) ) return NULL;

  fd = file_open(name:file, mode:"r");
  if (!fd) return NULL;

  main_index = file_read_dword(fd:fd);

  for (i=0; i<main_index; i++)
  {
    c = file_read(fp:fd, length:1);
    offset = file_read_dword(fd:fd);
    length = file_read_dword(fd:fd);

    if (c == first)
    {
      file_seek(fp:fd, offset:offset);
      sec_index = file_read_dword(fd:fd);

      for (j=0; j<sec_index; j++)
      {
        c = file_read(fp:fd, length:1);
        offset = file_read_dword(fd:fd);
        length = file_read_dword(fd:fd);

        if (c == second)
        {
          file_seek(fp:fd, offset:offset);
          tmp_list = file_read(fp:fd, length:length);

          len = strlen(tmp_list);
          pos = 0;

          for (j=0; j<len; j+=10)
            list[pos++] = substr(tmp_list, j, j+9);
          break;
         }
      }
      break;
    }
  }

  file_close(fd);

  return list;
}

function is_vulnerable_fingerprint(type, fp)
{
  local_var list, i, len;

  list = find_hash_list(type:type, first:fp[0], second:fp[1]);
  if (isnull(list))
    return FALSE;

  len = max_index(list);

  for (i=0; i<len; i++)
    if (list[i] == fp)
      return TRUE;

  return FALSE;
}

function wrapline()
{
  local_var ret;
  local_var i, l, j;
  local_var str;
  str = _FCT_ANON_ARGS[0];
  l = strlen(str);
  for ( i = 0 ; i < l; i += 72 )
  {
    for ( j = 0 ; j < 72 ; j ++ )
    {
       ret += str[i+j];
       if ( i + j + 1 >= l ) break;
    }
    ret += '\n';
  }
  return ret;
}

function get_key()
{
  local_var pub, public, pubtab, num, i, line,blobpub,fingerprint,ret ;
  local_var file_array, keyfile, filename, home, text;
  local_var pub_array;
  local_var report;
  local_var home_report;
  local_var flag;
  local_var path;
  local_var file;

  text = _FCT_ANON_ARGS[0];
  if ( ! text ) return NULL;
  home_report = NULL;
  home = split(text, keep:FALSE);
  home = home[0];
  if(home[strlen(home)-1] == "/") home += ".ssh/";
  else home += "/.ssh/";
  file_array = split(text, sep:"## ", keep:FALSE);
  foreach keyfile (file_array)
  {
    line = 0;
    flag = 0;
    pub_array = split(keyfile, keep:FALSE);
    filename = pub_array[0];
    report = '\n'+"In file " + home + filename + ':\n';
    foreach pub ( pub_array )
    {
      if ("# NOT FOUND" >< pub || "id_dsa.pub" >< pub || "id_rsa.pub" >< pub || "authorized_keys" >< pub || "### FINISHED" >< pub)
        continue;

      line ++;
      if ( pub !~ "ssh-[rd]s[sa]" ) continue;
      public = ereg_replace(pattern:".*ssh-[rd]s[sa] ([A-Za-z0-9+/=]+) .*$", string:pub, replace:"\1");
      if ( public == pub ) continue;

      blobpub = base64decode(str:public);
      fingerprint = substr(MD5(blobpub), 6, 15);
      if ("ssh-rsa" >< blobpub)
      {
        ret = is_vulnerable_fingerprint(type:SSH_RSA, fp:fingerprint);
        if (ret)
        {
          report += "line " + line + ':\n' + wrapline(pub);
          flag ++;
        }
      }
      else
      {
        ret = is_vulnerable_fingerprint(type:SSH_DSS, fp:fingerprint);
        if (ret)
        {
          report += "line " + line + ':\n' + wrapline(pub);
          flag ++;
        }
      }
    }
    if( flag > 0 ) home_report += report;
  }

  if ( empty_or_null(home_report) ) return NULL;
  return home_report;
}

# Decide transport for testing
if (islocalhost())
{
  if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

# ignore mountpoints if thorough tests is not enabled
if (!thorough_tests)
  cmd = info_send_cmd(cmd:'cat /etc/passwd | cut -d: -f6 | grep -v "[;&|'+"\"+'`$]" | while read h; do ( ! mountpoint $h > /dev/null 2>&1;) && [ -d "$h/.ssh" ] && echo "### HOME: $h" && (for f in id_rsa.pub id_dsa.pub authorized_keys; do echo "## $f"; cat "$h/.ssh/$f" 2>/dev/null || echo "# NOT FOUND"; done); done; echo "### FINISHED"');
else
  cmd = info_send_cmd(cmd:'cat /etc/passwd | cut -d: -f6 | grep -v "[;&|'+"\"+'`$]" | while read h; do [ -d "$h/.ssh" ] && echo "### HOME: $h" && (for f in id_rsa.pub id_dsa.pub authorized_keys; do echo "## $f"; cat "$h/.ssh/$f" 2>/dev/null || echo "# NOT FOUND"; done); done; echo "### FINISHED"');

if ( ! cmd || "## id_rsa.pub" >!< cmd)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, "Failed to get the contents of the /etc/passwd file.");
}
homes = make_list();

foreach home ( split(cmd, sep:"### HOME: ", keep:FALSE) )
{
  homefold = split(home, keep:FALSE);
  homefold = homefold[0];
  if(empty_or_null(homefold) || homes[homefold]) continue;
  else homes[homefold] = home;
}

foreach home ( homes )
{
  report += get_key(home);
}

if (info_t == INFO_SSH) ssh_close_connection();

if (report)
{
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else
  audit(AUDIT_HOST_NOT,"affected");
