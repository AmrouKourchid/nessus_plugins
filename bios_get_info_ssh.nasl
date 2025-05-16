#TRUSTED 22d46bbce6f5239016032b6faee1869ab892949c7571a4d4d1ef3826fa270c6592511082a6e4657c686bb393d65776f263d449e27b95cd7676b69fd0ac0413899ccdedca422c87a895bb90d463a8a03dd5e556ec473f3d960c937b62bf2c6bd8f45b81592feaef3f2ccae635a59e9b91d0b20a38db75668293403ff99c0222563c2aead436d49c9c0c2ad766dc310d4458a69827c5fa496d575abfb55d1e7c8bc1c69caa51ab4cd4946a5d0e0b2efafa2a74ac010f3ad82731b5fa178ae616dae7f17ec4516233c870ca7f4722af940a2011029a6087a793f75334d59db6c6ea02421572d8ae80ce97198642cb278345dbb664f3f9ae39a4b2b65bfe1838eecaaf6d241c733de2216bc9ef8503ab1232012dc798edca751d8f76387056abf0015e3a66cfbb0fc0d104e82358ceb902a092bfd0877ab2cda4b3331317d734f066451223777f72a0741c0301551e0f1a47fee50cfecc9887aac055b13b5a70ee8425f5ce88b7af1a0356c787565cf09d3907ecc9f7444cfb1da9341fc9017d768c09449cc632283c8a312ac50aff88e62fc6bc6e02b4e4d1345fbb0fc07efb9f67b6c86da0ab0715c6bf00ccaf628ae0d4579af3616d0c63f1a7cadd1b533a92b4e7eaafad1770bcf91541c23c690b7bae42eecd16ba38f7e68cbef7567149a568dcc4fc9d246d6f90aadc4b1adb7ed5c37cf728d442b9781b4f568ebbbdcd98c7
#TRUST-RSA-SHA256 9fff2cee571541935352fd3466fb7a25f68d7d50a9dce26db6cfb8bd5f313eb72b7399eba65da150db3df9808b0ab7b9ccc84fd5a0a7297c9943c1bcd2c1b182be26ebd73270a900fc152076e93669a8f0570ae8a00b8e73f703de6ba8c465bb8fa002418246d19d1fd0d32dbbde0e922c1b636cdbbbe18a49c1a78b8ccf7efe2e100164d54c81602d9e85dd7e3cbef9333efaffa98d90ab88f75f5b7b6205673f689f7591e1f0adcadf927bed78e10fcf0540b635fa2a2d4818265474b7fb82b3374575cbb801ea170b9bf5457769692dcd5217450d9055af135f7a7ba1ab46b4d3cdfb085630e820ad06de3099985463dfee665931d45b29deeef09a58c203ca47534130f21fcb759a83f1a00837439191e42ad53454dfccf4efc82a7241e480ff688de07a21cdef350c736332ee7cd42e36d1f547db3a7dddf62a10696dc1e5028fdf604c4ae893e6bd4251875da6e0bc3b5d7dc9f7d78d970cf8c3a2326026514793bc10ce743737619b806860b4f86ceafef23e2e1677c8564dd5bf8296e7ce010d5906ec2a4c7beb843afa32a9592e5e368c730ed4fd9f205566781496b50e140b221469873f7cebfd70ed7f630647dc24820300c49b417161d1fc04850cf89a5eef0e79b4747cd1a9c1df630468a4e167bd6b8300a4a862bf6cd3875718d5f6fc7c152e13173b8dec8f421dc7e2277aef97b06c34bf2fa2ec590e91f2
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(34098);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/12");

  script_name(english: "BIOS Info (SSH)");
  script_summary(english: "Get BIOS info using command line");

  script_set_attribute(attribute:"synopsis", value: "BIOS info could be read.");
  script_set_attribute(attribute:"description", value: "Using SMBIOS and UEFI, it was possible to get BIOS info.");
  script_set_attribute(attribute:"solution", value:"N/A");
  script_set_attribute(attribute:"risk_factor", value: "None");
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/08");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2008-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english: "General");

  script_dependencies("ssh_settings.nasl", "ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/OS/uname");
  script_require_ports("Services/ssh", 22, "nessus/product/agent");
  script_exclude_keys("BIOS/Vendor", "BIOS/Version", "BIOS/ReleaseDate");
  exit(0);
}
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("debug.inc");

# Exit fast as possible
get_kb_item_or_exit('Host/OS/uname');

# do ALL of the KB values we know how to fetch exist?
if ( get_kb_item("BIOS/Vendor") &&
     get_kb_item("BIOS/Version") &&
     get_kb_item("BIOS/ReleaseDate") &&
     get_kb_item("BIOS/SecureBoot") )
{
  # ALL of the KB values we know how to fetch exist, exit
  exit(0, "BIOS information already collected according to KB items." );
}

# Carry on
enable_ssh_wrappers();

function get_uuid_from_buf(buf)
{
  var uuid_regex, match;
  uuid_regex = "^(\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b)$";
  if (!empty_or_null(buf))
  {
    match = pregmatch(pattern:uuid_regex, string:buf);
    if (empty_or_null(match)) return NULL;
    else return match[1];
  }
  return NULL;
}


# We may support other protocols here
info_connect(exit_on_fail:TRUE);

# I planned initialy to run 
#  dmidecode -s bios-vendor 
#  dmidecode -s bios-version 
#  dmidecode -s bios-release-date
# Unfortunately, not all versions of dmidecode support the "-s" option.
# dmidecode -t 0 (which gives only BIOS information) is not supported
# everywhere either. So we have to parse the whole output.

# Work around broken $PATH
var dirs = make_list( "", "/usr/sbin/", "/usr/local/sbin/", "/sbin/");
var keys = make_list("Vendor", "Version", "Release Date");
var values = make_list();
var found = 0;
var cmd, buf, lines, v, uuid, drop_flag, pat, bios_date;

foreach var d (dirs)
{
  cmd = 'LC_ALL=C ' + d + 'dmidecode';
  dbg::log(msg:'Trying to run dmidecode with command: ' + obj_rep(cmd) + '\n');
  buf = info_send_cmd(cmd: cmd);
  if ('BIOS Information' >< buf)
  {
    lines = split(buf, keep: 0);
    drop_flag = 1;
    foreach var l (lines)
    {
      if (preg(string: l, pattern: '^BIOS Information'))
      {
        drop_flag = 0;
        continue;
      }
      else
      {
        if(preg(string: l, pattern: '^[A-Z]'))
        {
          drop_flag = 1;
        }
      }
      if (drop_flag)
      {
        continue;
      }

      foreach var k (keys)
      {
        pat = '^[ \t]+' + k + '[ \t]*:[  \t]*([^ \t].*)';
        v = pregmatch(string: l, pattern: pat);
        if (! isnull(v))
        {
          values[k] = v[1];
          found++;
        }
      }
    }
  }
  if (found > 0)
  {
    break;
  }
}

#
# UEFI spec
# http://www.uefi.org/sites/default/files/resources/UEFI%20Spec%202_7_A%20Sept%206.pdf
# SecureBoot BS, RT Whether the platform firmware is operating in Secure boot mode (1) or not (0). All other values are reserved. Should be treated as read-only.
# 
# Using * because sometimes vendors overload the global variable ID
# /sys/firmware/efi/efivars/SecureBoot-*
# if it exist:
# 06 00 00 00 01  -> 4 bytes for 32 bit access mask then 1 byte value (enabled)
# 06 00 00 00 00  -> 4 bytes for 32 bit access mask then 1 byte value (disabled)
#
dirs = make_list( "", "/bin/", "/usr/bin/", "/usr/local/bin/" );
var bootSecure = "unknown";
foreach d (dirs)
{
  # 06 00 00 00 01
  cmd  = 'LC_ALL=C 2>/dev/null ' + d + 'od -An -t x1 /sys/firmware/efi/efivars/SecureBoot-*';
  cmd += ' || ';
  cmd += 'LC_ALL=C 2>/dev/null ' + d + 'hexdump -ve \'10/1 "%02x " "\n" \' /sys/firmware/efi/efivars/SecureBoot-*';
  cmd += ' || ';
  cmd += 'LC_ALL=C [ ! -d /sys/firmware/efi ] && echo "06 00 00 00 00"';
  var otherBuf = info_send_cmd(cmd: cmd);
  dbg::log(msg:'Checking UEFI secureboot with command: ' + obj_rep(cmd) + '\n  Received: ' + obj_rep(otherBuf) + '\n');
  lines = split(otherBuf, keep: 0);
  foreach l (lines)
  {
    # od or hexdump both report this format for enable
    if ( preg( string:tolower(l), pattern:"06 00 00 00 01" ) )
    {
      bootSecure = "enabled";
      break;
    }
    # od or hexdump both report this format for disabled
    if ( preg( string:tolower(l), pattern:"06 00 00 00 00" ) )
    {
      bootSecure = "disabled";
      break;
    }
  }
  if ( bootSecure != "unknown" )
  {
    # we have the answer stop looking
    replace_kb_item(name: 'BIOS/SecureBoot', value: bootSecure);
    break;
  }
}

# Parse UUID from dmidecode output
uuid = pgrep(pattern:'^[\t ]*UUID[ \t]*:', string:buf);
if ( !isnull(uuid) )
{
  pat = '^[ \t]+UUID[ \t]*:[  \t]*([^ \t].*)';
  v = pregmatch(string: uuid, pattern: pat);
  if ( !isnull(v) )
  {
    uuid = v[1];
  }
  else
  {
    uuid = NULL;
  }
}

#
# Try to use alternate methods to obtain Version, Vendor, Release Date, UUID incase dmidecode failed
#
# UUID from /sys/hypervisor/uuid
var uuidBuf;
if (isnull(uuid))
{
  cmd  = 'LC_ALL=C 2>/dev/null cat /sys/hypervisor/uuid';
  uuidBuf = info_send_cmd(cmd: cmd);
  dbg::log(msg:'Reading uuid with command: ' + obj_rep(cmd) + '\n  Received: ' + obj_rep(uuidBuf) + '\n');
  uuid = get_uuid_from_buf(buf: uuidBuf);
  if (!isnull(uuid) && strlen(uuid) > 0) found++;
}

# UUID from /sys/devices/virtual/dmi/id/product_uuid
if (isnull(uuid))
{
  cmd  = 'LC_ALL=C 2>/dev/null cat /sys/devices/virtual/dmi/id/product_uuid';
  uuidBuf = info_send_cmd(cmd: cmd);
  dbg::log(msg:'Reading uuid with command: ' + obj_rep(cmd) + '\n  Received: ' + obj_rep(uuidBuf) + '\n');
  uuid = get_uuid_from_buf(buf: uuidBuf);
  if (!isnull(uuid) && strlen(uuid) > 0) found++;
}

# Vendor from /sys/devices/virtual/dmi/id/sys_vendor
if (empty_or_null(values) || empty_or_null(values['Vendor']))
{
  cmd  = 'LC_ALL=C 2>/dev/null cat /sys/devices/virtual/dmi/id/sys_vendor';
  var vendor = info_send_cmd(cmd: cmd);
  dbg::log(msg:'Reading vendor with command: ' + obj_rep(cmd) + '\n  Received: ' + obj_rep(vendor) + '\n');
  vendor = strip(vendor, pattern:'\n');
  if (!isnull(vendor) && strlen(vendor) > 0)
  {
    values['Vendor'] = vendor;
    found++;
  }
}

# Version from 
if (empty_or_null(values) || empty_or_null(values['Version']))
{
  cmd  = 'LC_ALL=C 2>/dev/null cat /sys/devices/virtual/dmi/id/product_version';
  var version = info_send_cmd(cmd: cmd);
  dbg::log(msg:'Reading version with command: ' + obj_rep(cmd) + '\n  Received: ' + obj_rep(version) + '\n');
  version = strip(version, pattern:'\n');
  if (!isnull(version) && strlen(version) > 0)
  {
    values['Version'] = version;
    found++;
  }
}

# Release Date from /sys/devices/virtual/dmi/id/bios_date
if (empty_or_null(values) || empty_or_null(values['Release Date']))
{
  cmd  = 'LC_ALL=C 2>/dev/null cat /sys/devices/virtual/dmi/id/bios_date';
  bios_date = info_send_cmd(cmd: cmd);
  dbg::log(msg:'Reading bios date with command: ' + obj_rep(cmd) + '\n  Received: ' + obj_rep(bios_date) + '\n');
  bios_date = strip(bios_date, pattern:'\n');
  if (!isnull(bios_date) && strlen(bios_date) > 0)
  {
    values['Release Date'] = bios_date;
    found++;
  }
}

if(info_t == INFO_SSH)
{
  ssh_close_connection();
}

if (found || 'BIOS Information' >< buf || 'System Information' >< buf)
{
  replace_kb_item(name: 'Host/dmidecode', value: buf);
}

if (!found)
{
  audit( AUDIT_NOT_DETECT, "BIOS info" );
}

var report = "";
foreach k (keys(values))
{
  var k2 = str_replace(string: k, find: " ", replace: "");
  if ( !empty_or_null(k2) && !empty_or_null(values[k]) )
  {
    replace_kb_item(name: "BIOS/" + k2, value: values[k]);
    report = report + k + crap(data: ' ', length: 12 - strlen(k)) + ' : ' + values[k] + '\n';
  }
}

if ( !isnull(uuid) )
{
  report = report + "UUID" + crap(data: ' ', length: 12 - strlen("UUID")) + ' : ' + uuid + '\n';

  if ( defined_func('report_xml_tag') )
  {
    report_xml_tag(tag:'bios-uuid', value:uuid);
    set_kb_item(name:"Host/Tags/report/bios-uuid", value:uuid);
  }
}

if ( !empty_or_null( report ) )
{
  report = report + "Secure boot" + crap(data: ' ', length: 12 - strlen("Secure boot")) + ' : ' + bootSecure + '\n';
  security_report_v4(port: 0, severity:SECURITY_NOTE, extra:report);
}
