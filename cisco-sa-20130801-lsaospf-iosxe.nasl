#TRUSTED 39b4b36772c83bce93771b8fbe49bd206bfc678437a53b8b507631ae5dfa7e6ddcfbbc6ad1b2874e5ea9fc0e21c800532754aae77a2e08e75a14fd1dbe35cdaf1d3340d69890e3329589629c799915b538c3a858243aebbf05c6a0f599b2bec972192a744d33ebf0187cdef0bce2b50e4aaffccad78b7b2fea3728e9af1e617ed94bf6b7c22433665710fb7d28c67dc6ca18d6784c92c164fecec2541a53e7b4f05b87220e112881c83975e374d5f60f3b88d21267914403f5d604214ef58857e42619b094d2ddebc9aa8aca96390abc0279eb788ad90904473e20b84a647a83e0bae940e49ade5da665ff60f7e8c48b9fede3181804c5fba89287e7143720217eb32c6982efeb37caa1282ae1e5a261eb41eb918f8458c8e04e019c969d7594be291c6b56bf3797645a1b62d7ffb813993da37c4f4fcf50dae22ae0094a356a76b2f17e32999164a473b4b154a9f4dca680f3d66a9c12b1ff533d3a7901640ee902ddcfab2b4de08bb79bf5a1680c57f9d6c1bf829ccdafc09191487e79eadbdffc00950afbd14c81671e9b5bfd3030c2f14765309c922e1f515beecc49303a8469c3606ee6a89ad61cb376fb8e5da0e7e974be9eaf32fcd7ca486f2e1ac0baccc3800147a210077233f82e30e23acaf2e33286496337405dbd57e4ddf2268c8ec4396e7938e30a2c039fcb1bd8c635d73c67921525da8814a756d9257b8d15
#TRUST-RSA-SHA256 75dc9fb66561aa67aa7f6ff7348b271e95aa2943728300fccaddbe57b741d2e587c9dd3942c0ecdf67fb9d142cbaadd144528407516102addcc18bbaae9dda6036c50a53c9b0b0d49549d498aecf35b718c6245db3bfa4363f67136b73756e48033bcacfeaa9eb9cdc08288424f93e6024179d0bd191492a68a02f28dec717138718ac6b8b2af2095883098df02d6f051fd7a678db5cfa5d61086fdeb8983169bb12416aa598442acb0fc48a280de9e99a9d03e1e909fcc8672700e74efa716282d4fb7ab8ba1da0dcd601703d0de20c0c8aa09b73d8357fb517b80b02f7707653491531983fba3e9289f51ad8c7836fc4a1ab5c167c50d3bf0b795e8ad77c558fdaf3bbfa439f3a4e5e30266b368bb9284d0c9941c4083155ceee23ec6a45f96912a59513b35a037fed41eaadbc3c987d49387cc6642617541a171331355a6983dcdb9f9148bcd95050ff297787c0b2218ebb8d9ce45e8bf1477754cb1cca5ddb1725f2a99c13a02317a5c119859b5ef52129fcba7f2d959fa8367d350256ab58c201088f8deb552eb7246eaf3169dddd60f977ce4f462edf95e48ecd8cc43df4f4ccfbda492095f93e2301ff986397d58ae8a151de25d1efb38f816eed41ba95a46f9bc8d6f39bd79806594161bf7b5e6cf85b666a97c78f97b2909d51311518ca29f02fd1f610bd94c9ab0df271d713d29ba8faa4d854e0c2a5a8dee7c737
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69378);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2013-0149");
  script_bugtraq_id(61566);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug34485");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130801-lsaospf");

  script_name(english:"OSPF LSA Manipulation Vulnerability in Cisco IOS XE (cisco-sa-20130801-lsaospf)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is affected by a vulnerability
involving the Open Shortest Path First (OSPF) Routing Protocol Link
State Advertisement (LSA) database. A remote, unauthenticated attacker
can exploit this vulnerability, via specially crafted OSPF packets, to
manipulate or disrupt the flow of network traffic through the device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130801-lsaospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a643e96");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20130801-lsaospf.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

#
# @param fix     The second version string.
# @param ver     The first version string.
# @param strip   A character/string which should be removed
#
# @return -1 if ver < fix, 0 if ver == fix, or 1 if ver > fix.
##
function ver_cmp(fix, ver, strip)
{
  local_var ffield, vfield, flen, vlen, len, i;

  # strip out any desired characters before the comparison
  if (strip)
  {
    ver = str_replace(string:ver, find:strip, replace:'');
    fix = str_replace(string:fix, find:strip, replace:'');
  }
  # replace ( and ) with dots to make comparisons more accurate
  ver = ereg_replace(pattern:'[()]', replace:".", string:ver);
  fix = ereg_replace(pattern:'[()]', replace:".", string:fix);
  # Break apart the version strings into numeric fields.
  ver = split(ver, sep:'.', keep:FALSE);
  fix = split(fix, sep:'.', keep:FALSE);

  vlen = max_index(ver);
  flen = max_index(fix);
  len = vlen;
  if (flen > len) len = flen;
  # Compare each pair of fields in the version strings.
  for (i = 0; i < len; i++)
  {
    if (i >= vlen) vfield = 0;
    else vfield = ver[i];
    if (i >= flen) ffield = 0;
    else ffield = fix[i];

    if ( (vfield =~ "^\d+$") && (ffield =~ "^\d+$") )
    {
      vfield = int(ver[i]);
      ffield = int(fix[i]);
    }
    if (vfield < ffield) return -1;
    if (vfield > ffield) return 1;
  }
  return 0;
}

flag = 0;
override = 0;
report_extras = "";
fixed_ver = "";

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

if (version =~ "^2(\.[0-9]+)?") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.1(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.1(\.[0-9]+)?SG$") {fixed_ver = "3.2.7SG" ; flag++; }
else if (version =~ "^3\.2(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.2(\.[0-9]+)?SE$")
{
  if (ver_cmp(ver:version, fix:"3.2.2SE", strip:"SE") < 0)
  {
    fixed_ver = "3.2.2SE";
    flag++;
  }
}
else if (version =~ "^3\.2(\.[0-9]+)?SG$")
{
  if (ver_cmp(ver:version, fix:"3.2.7SG", strip:"SG") < 0)
  {
    fixed_ver = "3.2.7SG";
    flag++;
  }
}
else if (version =~ "^3\.2(\.[0-9]+)?SQ$") {fixed_ver = "3.3.0SQ" ; flag++; }
else if (version =~ "^3\.2(\.[0-9]+)?XO$") {fixed_ver = "Refer to the Obtaining Fixed Software section of the Cisco advisory." ; flag++; }
else if (version =~ "^3\.3(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.3(\.[0-9]+)?SG$") {fixed_ver = "3.4.1SG" ; flag++; }
else if (version =~ "^3\.4(\.[0-9]+)?S$") {fixed_ver = "Refer to the Obtaining Fixed Software section of the Cisco advisory." ; flag++; }
else if (version =~ "^3\.4(\.[0-9]+)?SG$")
{
  if (ver_cmp(ver:version, fix:"3.4.1SG", strip:"SG") < 0)
  {
    fixed_ver = "3.4.1SG";
    flag++;
  }
}
else if (version =~ "^3\.5(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.6(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.7(\.[0-9]+)?S$") {fixed_ver = "Refer to the Obtaining Fixed Software section of the Cisco advisory." ; flag++; }
else if (version =~ "^3\.8(\.[0-9]+)?S$")
{
  if (ver_cmp(ver:version, fix:"3.8.2S", strip:"S") < 0)
  {
    fixed_ver = "3.8.2S";
    flag++;
  }
}
else if (version =~ "^3\.9(\.[0-9]+)?S$")
{
  if (ver_cmp(ver:version, fix:"3.9.1S", strip:"S") < 0)
  {
    fixed_ver = "3.9.1S";
    flag++;
  }
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ospf_interface", "show ip ospf interface");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"line protocol is up", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Installed release : ' + version +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
