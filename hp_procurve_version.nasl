#TRUSTED a39b2556281cceb84baefb1ae9bf68a70e8aeaaf3a6969bcd67ab0c71ae19d47b640453dfd835794ba2ba7269e66044216d3299e15679e9b15b8e65a04e82e8e7940ab0659a2ff4c8ec77d9c82a206add043d0ce821066371fcc45e31eaa6c78edb3fdfc30f114e0b46df6643ca8c56f52f340e660c9dd82d0538fb3db46f07f154f028f78fd4bb9ffb0c2ba38231b41cc3d58ad182e7fc69947f990e981765b53566476cfcf1f3acef60cd75be29c3e4ec0cfc7d98583de9b0a3c1039fdeae17b882f2b98bb5b1e804d540089ebf4944a5786e9abd971642fe553c83467e7a7d8c844c119bbe3b163c2dea557b07b412b52f37884f5534a95205de81172fc03c291413a5179da865eca9782d567a88c3563b3a9d9e4f68a56785445ca1ef4a600eaf1004587d232f1bd11f43c443c58e45b9cc136c1f30dfd52f99d7e0dc0d139ec379992ac5eb1ee26168e52ab2b5e950c64a145ad1d9922c7d1ca5e2ce75177d1c3d3d123dc18243f8d7c84c7c42c099c21d8d9e78a6fe000e320d915794d4064b6c864f4715f4b1c15ffa13bacc944351b5ddc5f7ebcb63e23fb69ef6739ea15123d1eefecb8e2e244b188937bcbc1d00e93bece19d9fa9498ad0a1777f574625bf90950d411323c3a24ee969e7bb20272db556c40d8c31acb91877237c0961b64ba700cf047db1972f0f953677578d35a32b1038d8e7c75f99a7885c1f6
#TRUST-RSA-SHA256 07ff232efe5148ce67c401df8bbe9ea4a70cc9345266946d2d5aeaad51b493349a96ad5b8e37a09cac1a55c3aff5b40851722f352141b2ea9deeac08c9d2ec4e6faf6b427bbccd049702a337c198f7b7d18071bdaacc34427782d79da9edc0d29c216f06cd4588709c4416af8b1e2edfb6c23f4e6e4f3118e320be7360627afe393ef65a74d5d208bcca0d32eb19ed0a53884330959e1fdcd665e5989d6bc98a7cd4c88df45922ec918345c2f464f9607e37ee2c58b485de29003aa87c55230d3ee07d6841f7b01d05d400ef975693f9bd901c54d0c16e505e5f4f88426bd3d1382c8105af770e70b09c6c2b4bb5bb7813815a5c352be3a9cac7a17fde2b8152d9c103cb858e408ecfacc967e1f942b648b739aedb148210d7e929a4d7d7eceb38ae0db15502e678d5998a61821a29974d7c8d30569c36c1296ace304fe2ad86f989a66d06fea595cd7ad865dc78262e754ee860f2fc903c07b1450893b8a8f39dcd924358de4686ba45fba6d841b7e4ed3efa0bcbb4c4b48de2537ddca218628fe63ba4c1270a1203b1531a771034e8d86fe806f27508f60fcef2755e3f5989c5b414cb2f7a27ba3758d86fd04f415f4f05c408d7cc1cd7196c9afcb1f8986f0e21321849689e966bf7ea512656342f2464050c84b656ddb45bdad0babb7a96ef7617c5e0decd42aedc3fd86e298b9f93d52867afe630ac2794d600e74d7cdc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(69322);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

 script_name(english:"HP Switch Identification");
 script_summary(english:"Obtains the version of the remote HP switch");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the model, serial number and / or software
version for the remote HP switch.");
 script_set_attribute(attribute:"description", value:
"The remote host is an HP switch. It is possible to read the model,
serial number, and/or software version by connecting to the switch via
SSH or by using SNMP.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:procurve_switch");

 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"hardware_inventory", value:"True");
 script_set_attribute(attribute:"os_identification", value:"True");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Service detection");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl");
 script_require_ports("Host/HP_Switch", "SNMP/sysDesc");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");

var rev = "";
var sn = "";
var model = "";
var model2 = "";
var comware = 0;

# 1. check SSH
if ( get_kb_item("Host/HP_Switch/show_modules") )
{
  txt = get_kb_item("Host/HP_Switch/show_modules");
  match = pregmatch(pattern:"Chassis:[ \t]*([^ ]+) ([^ ]+)", string:txt);
  if (!isnull(match))
  {
     model = match[2];
     model2 = match[1];
  }
  match = pregmatch(pattern:"Serial Number:\s+([^ ]+)", string:txt);
  if (!isnull(match)) sn = match[1];
}
if ( get_kb_item("Host/HP_Switch/show_system") )
{
  txt = get_kb_item("Host/HP_Switch/show_system");
  match = pregmatch(pattern:"Software revision[ \t]*:[ \t]*([^ \n\r]+)", string:txt);
  if (!isnull(match)) rev = match[1];
  match = pregmatch(pattern:"Serial Number\s*:\s+([^ ]+)", string:txt);
  if (!isnull(match) && !sn) sn = match[1];
}
if ( get_kb_item("Host/HP_Switch/show_tech") )
{
  txt = get_kb_item("Host/HP_Switch/show_tech");
  match = pregmatch(pattern:"Software revision[ \t]*:[ \t]*([^ \n\r]+)", string:txt);
  if (!isnull(match)) rev = match[1];
  match = pregmatch(pattern:"Serial Number\s*:\s+([^ ]+)", string:txt);
  if (!isnull(match) && !sn) sn = match[1];
  match = pregmatch(pattern:";[ \t]*([^ \n\r]+)[ \t]*Configuration Editor;", string:txt);
  if (!isnull(match) && !model) model = match[1];
}
if ( get_kb_item("Host/HP_Switch/summary") ) # used for Comware systems
{
  txt = get_kb_item("Host/HP_Switch/summary");
  match = pregmatch(pattern:"HPE? ([^ ]+) Switch", string:txt);
  if (!isnull(match))
  {
    if (!model2) model2 = match[1];
    comware++;
  }
  match = pregmatch(pattern:"Comware Software, Version ([0-9][0-9.]+),? Release ([^\s,]+)", string:txt);
  if (!isnull(match))
  {
     if (!rev) rev =  match[1] + " Release " + match[2];
    comware++;
  }
}
if ( get_kb_item("Host/HP_Switch/show_ver") )
{
  txt = get_kb_item("Host/HP_Switch/show_ver");
  temp_array = split(txt);
  foreach var temp_str (temp_array)
  {
    match = pregmatch(pattern:"\s+([A-Z]+\.[0-9]+(\.[0-9]+)*)", string:temp_str);
    if (!isnull(match)) rev = match[1];
    else
    {
      match = pregmatch(pattern:"\s+([A-Z]+[0-9]+(\.[0-9]+)*)", string:temp_str);
      if (!isnull(match)) rev = match[1];
      else
      {
        match = pregmatch(pattern:"\s+([0-9]+\.[0-9]+\.[0-9A-Za-z]+)", string:temp_str);
        if (!isnull(match)) rev = match[1];
      }
    }
  }
}
if ( get_kb_item("Host/OS/showver") )
{
  txt = get_kb_item("Host/OS/showver");
  match = pregmatch(pattern:"HPE? (.*) Switch \((.*)\)(.*)", string:txt);
  if (!isnull(match))
  {
    if (!model) model = match[2];
    if (!model2) model2 = match[1];
    if (match[3] && !rev) rev = match[3] - " with software revision ";
  }
  else
  {
    # match for Comware systems
    match = pregmatch(pattern:"HPE?\s\s*([^\s]+)\s\s*.*Switch\s\s*.*[Vv]ersion,?\s\s*([0-9][0-9.]+)\s\s*[Rr]elease\s\s*([^ ,]+)", string:txt);
    if (!isnull(match))
    {
      if (!model2) model2 = match[1];
      if (match[3] && !rev) rev = match[2] + " Release " + match[3];
      comware++;
    }
  }
}

# 2. check SNMP
if ( (!model) || (!model2) || (!sn) || (!rev) )
{
  community = get_kb_item("SNMP/community");
  if (community)
  {
    port = get_kb_item("SNMP/port");
    if(!port)port = 161;
    if (! get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

    soc = open_sock_udp(port);
    if (soc)
    {
      # validate that we are indeed looking at a HP device
      txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.2.1");
      if (txt)
      {
        match = pregmatch(pattern:"^HPE?\s+[^\s]+\s+Switch", string:txt);
        if (!isnull(match))
        {
          # get hardware model
          if (!model)
          {
            txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.11.2.36.1.1.2.5.0");
            if (txt)
            {
              model = txt;
              set_kb_item(name:"SNMP/hardware", value:txt);
            } else {
              # match for Comware systems
              txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.7.1");
              if (txt)
              {
                # HP|HPE V1910-16G Switch JE005A
                match = pregmatch(pattern:"HPE?\s+([^\s]+)\s+Switch\s+(.*)", string:txt);
                if (!isnull(match))
                {
                  model = match[2];
                  if (!model2) model2 = match[1];
                  set_kb_item(name:"SNMP/hardware", value:model);
                  comware++;
                }
              }
            }
          }
          # get serial number
          if (!sn)
          {
            txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.11.2.36.1.1.2.9.0");
            if (txt) sn = txt;
            else
            {
              # match for Comware systems
              txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.11.1");
              if (txt)
              {
                sn = txt;
                comware++;
              }
            }
          }
          # get Software version
          if (!rev)
          {
            txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.4.1.11.2.36.1.1.2.6.0");
            if (txt) rev = txt;
            else
            {
              # match for Comware systems
              # 5.20 Release 1111P02
              txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.7.1");
              if (txt)
              {
                rev = txt;
                comware++;
              }
            }
          }
        }
      }
    }
  }

  if ( (!model) || (!model2) || (!rev) )
  {
    sys = get_kb_item("SNMP/sysDesc");
    if (sys)
    {
      match = pregmatch(pattern:"HPE?\s\s*([^\s]+)\s\s*.*Switch\s\s*([^\s,]+),\s\s*revision\s\s*([^\s,]+)", string:sys);
      if (!isnull(match))
      {
        if (!model) model = match[1];
        if (!model2) model2 = match[2];
        if (!rev) rev = match[3];
      }
      else
      {
        # match for Comware systems, later revsions updated from HP to HPE and added a comma after Version 5.20,
        # HP V1910-16G Switch Software Version 5.20 Release 1111P02
        # HP V1910-16G Switch with Comware software version 5.20 release 1111P02
        match = pregmatch(pattern:"HPE?\s\s*([^\s]+)\s\s*.*Switch\s\s*.*[Vv]ersion\s\s*([0-9][0-9.]+),?\s\s*[Rr]elease\s\s*([^ ,]+)", string:sys);
        if (!isnull(match))
        {
          if (!model2) model2 = match[1];
          if (!rev) rev = match[2] + " Release " + match[3];
          comware++;
        }
      }
    }
  }
}

# if model is not defined but model2 is, then set model = model2
if ( (!model) && (model2) )
{
   model = model2;
   model2 = "";
}

# 3. Exit if no software version was found
if (rev == "") rev = "unknown";
if ( (isnull(rev)) || (!rev) || (rev == "unknown") )
  exit(1, "This is not an HP Switch.");

# 4. Set KBs if found
set_kb_item(name:"Host/HP_Switch/SoftwareRevision", value:rev);
if (isnull (sn) || sn == "") sn = "unknown";
set_kb_item(name:"Host/HP_Switch/SerialNumber", value:sn);
if (isnull(model) || model == "") model = "unknown";
set_kb_item(name:"Host/HP_Switch/Model", value:model);

if ( (! get_kb_item("Host/OS/showver") ) && (model2) )
{
    if (!comware)
      set_kb_item(name:"Host/OS/showver", value:"HP " + model2 + " Switch (" + model + ") with software revision " + rev);
    else
      set_kb_item(name:"Host/OS/showver", value:"HP " + model2 + " Switch with Comware Software version " + rev);

    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"switch");
}

replace_kb_item(name:"Host/HP_Switch", value:TRUE);

if ( (model2) && (model != model2) )  model = model + " (" + model2 + ")";

if (report_verbosity > 0)
{
  report = '\n  Model #           : ' + model +
           '\n  Serial #          : ' + sn +
           '\n  Software revision : ' + rev +
           '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
