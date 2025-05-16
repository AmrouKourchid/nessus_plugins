#TRUSTED 21cbfaec342f8adee661bd7e8411cee3426e9bb28cd61658acf441687d6c0bccd5ca59c9c3e15917b9e03951ad1e4099af9558fd447229c3ce367a4f855b272894bfe9aab14c1721d4bb1e559a845b5e15c3c533bda8ae4d8fc9d7d338012ba914767f65d910b45763ef7f866563071f2be33e365a2cffa817eb52131005bbf299f92306a488a5f77177e299962cb55846cba45ed5734a7704da21a5bc0e71fc9a20d54a76135c4569eabb2d38fe9868e68319606f1f82f3bc67f2ff2ca92e033b18c1bc272adec180866b01c406e4ac97b2a6016a8ec1bc1afafb6f7a9d4e3f718ae51610ba1ca4a148702689a5db1810b173c54c59c6d3d055b94697220631575ee1520c602955a5a65c5a958ad57617af42b15968c41bad6e5bcf141c569f5be8cfde4b96c03035edda91c5120893478ad639c330a54475a11b0c75c86299eaf89980dc787c3e3068e3ad128bb4ab75663d72c34e92a9f1719d71e0c9ad1439a26640d9d69b423a69ee6e791827077e36a54502561cf798f9f8c49e2acb395f1b77a459ed2252498164575484d03afe663906cf3238aa565954f24bddacb01e9c38c196e3bb09db1595fdc46088da5e571c99dde66fdb75fd044168e3008ac291534f8d278333e61728f5d0cfcb79d3105f13da82034649acac5144848259dac0db3986f30e7db7c734a7cb1ec76b3f9ccf9278679d9f2e8ea393a3e63b10
#TRUST-RSA-SHA256 156cc7d2c4e2f345b18e863dff117a54d0cf8f14cdf745223738c7060eb74e7589bd01990b172f07db1df1191f2ba5a9a5f5826605ecbafde6778d0b9161599c91e5267e0124b98979a6b6287a4c7d8af6cddd95aa6a5d5d67658ae91b9fe18979460c7719beaf33bd1b7f8c7f453221753e7e5676972521c66a0ff8213b73a4eab0515a2b491093f9c268721f3dfba896caacc0b9a8f6cf2731796a6eeffe26017f3a97a2472f969fcfe01b4f55fe77000bd5bdcf31f21dbfafe8572537169d49de9a7d6e28834e4015bb2e82626971993454ce5fb9aa5cc5a3c91e39a226605115466e14521ae6ec533a4e5c58ea0506e4fe8a1cc4e97568aa72dc4a9ba67eb037ead4275bd7ac1de00c2d280101b2457cd55c47f952a7fd991f9bb2795d5a54a0ea6a79ff2edae03ae63deea60de1746e5e1f328bea78269d35ab3393d3e40511397d3e83a830c1f5fd4b0c0e5886dc696d7d98a6b2fe50045034420884edb11e60d9ea366642c6b79b9fbb4ea18c036f29fbb32df3eeb71dc3b8b1993608aacf6d8ee603a5a2f19f0fd69f663ca114287bed99b545062c9485e92aaf1510168f4db549847d0d49acb2df951a6d223ef55f38cd895d7ca3d6b744ab5a10253ce2faaabcb66178d8fce1d0522e9ac8dbd4789d82380451e0bf310332173dcc98afc9d845ff103098f5ddcd00cffd5cdf82f1e99e19c9a589d91eae9a644a34
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64913);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"SSHD libkeyutils Backdoor");
  script_summary(english:"Checks for evidence of a libkeyutils library being trojaned");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host may be compromised."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host appears to contain a trojaned libkeyutils library.  The
trojaned library links to SSHD, steals credentials, and sends spam."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.webhostingtalk.com/showthread.php?t=1235797");
  # http://blog.solidshellsecurity.com/2013/02/18/0day-linuxcentos-sshd-spam-exploit-libkeyutils-so-1-9/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f62cb60d");
  # http://contagiodump.blogspot.com/2013/02/linuxcentos-sshd-spam-exploit.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b03816df");
  # https://isc.sans.edu/diary/SSHD%20rootkit%20in%20the%20wild/15229
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4958f5dd");
  script_set_attribute(attribute:"see_also", value:"http://www.webhostingtalk.com/showpost.php?p=8563741&postcount=284");
  script_set_attribute(
    attribute:"solution",
    value:
"Verify whether or not the system has been compromised.  Restore from
known good backups and investigate the network for further signs of a
compromise, if necessary."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("telnet_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");


enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# public reports indicate only RPM-based distros have been infected
rpm_list = get_kb_list_or_exit('Host/*/rpm-list');
rpm_list = make_list(rpm_list);
rpm_list = split(rpm_list[0], sep:'\n', keep:FALSE);

keyutils_rpms = make_list();

foreach line (rpm_list)
{
  fields = split(line, sep:'|', keep:FALSE);
  rpm = fields[0];
  if (rpm =~ "^keyutils-libs-\d")
    keyutils_rpms = make_list(keyutils_rpms, rpm);
}

if (max_index(keyutils_rpms) == 0)
  audit(AUDIT_NOT_INST, 'keyutils-libs');

# initialization required for using info_send_cmd()
if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF, 'pread');
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

affected_files = make_array();
rpm_verify = make_array();

foreach rpm (keyutils_rpms)
{
  # verify the files in the rpm package
  rpm_cmd = '/bin/rpm -Vv ' + rpm;
  rpm_output = info_send_cmd(cmd:rpm_cmd);
  output_lines = split(rpm_output, sep:'\n', keep:FALSE);

  foreach line (output_lines)
  {
    # determine if the size and md5sum of any library files have changed
    match = eregmatch(string:line, pattern:"^S.5......\s+(/lib(64)?/libkeyutils.+)$");
    file = match[1];
    if (isnull(file)) continue;

    # if so, check if the file contains the encoded IP address associated with this backdoor.
    # the string below is 78.47.139.110 - each byte is xor'd with 0x81
    encoded_ip = "\xb6\xb9\xaf\xb5\xb6\xaf\xb0\xb2\xb8\xaf\xb0\xb0\xb1";
    cmd = "/bin/grep -P '" + encoded_ip + "' " + file + ' &> /dev/null ; /bin/echo $?';
    results = info_send_cmd(cmd:cmd);

    if (chomp(results) == '0') # avoid false negatives by checking the exit status
    {
      affected_files[file] = cmd;
      rpm_verify[rpm_cmd] = rpm_output;
    }
  }
}

ssh_close_connection();

if (max_index(keys(affected_files)) == 0)
  audit(AUDIT_HOST_NOT, 'affected');

if (report_verbosity > 0)
{
  if (max_index(keys(affected_files)) == 1)
    s = ' appears';
  else
    s = 's appear';

  report =
    '\nThe following file' + s + ' to contain backdoor code :\n\n' +
    join(sort(keys(affected_files)), sep:'\n') +'\n\n' +
    'This was determined by verifying any libkeyutils RPM packages :\n\n' +
    join(sort(keys(rpm_verify)), sep:'\n') + '\n\n' +
    join(sort(make_list(rpm_output)), sep:'\n') + '\n' +
    'And checking if any modified library files contain a string which\n' +
    'can be decoded to "78.47.139.110" (an IP address associated with the\n' +
    'backdoor) :\n\n';
  foreach key (sort(keys(affected_files)))
    report += affected_files[key] + '\n';

  security_hole(port:0, extra:report);
}
else security_hole(0);
