#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50577);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_name(english:"Ricoh Printer Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a printer.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Ricoh Printer.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("http.inc");
include('install_func.inc');

#
# Handles the scenario, where there is an OT device, in front of the printer.
# If the target is treated as OT, "Host/dead" KB, will not be set, by dont_scan_printers.nasl.
# Instead, the plugin would check Do_Scan_Printers, Scan/Do_Scan_OT and Scan/Do_Scan_Novell.
#
var scan_kb_list = get_kb_list("Scan/*");
foreach var check_flag (keys(scan_kb_list))
{
  if 
  ((check_flag == "Scan/Do_Scan_Printers") && (get_kb_item(check_flag) == FALSE) || 
  (check_flag == "Scan/Do_Scan_OT") && (get_kb_item(check_flag) == FALSE))
  {
    exit(0,"Ricoh printer marked as do not scan -- there could be an OT device in front of this printer.");
  }
  else if (get_kb_item(check_flag) == TRUE)
  {
    dbg::detailed_log(lvl:2, msg: check_flag + " is set to TRUE - this device will be scanned.");
  }
}

var path = '/';
var port = get_http_port(default:443, dont_break:1);

var res = http_get_cache(port:port, item:'/', exit_on_fail:FALSE);
var banner = get_http_banner(port:port, exit_on_fail:FALSE);

if ("Web-Server/" >!< banner && 'websys/webArch/mainFrame.cgi' >!< res)
  audit(AUDIT_WEB_APP_NOT_INST, 'Ricoh printer', port);

var kb_base = "www/ricoh";

var labels = {};

labels['model'] = "Model";
labels['mid'] = "Machine ID";
labels['sysver'] = "System Version";
labels['nibver'] = "NIB Version";
labels['wimver'] = "Web Image Monitor Version";

# Collect various pieces of data
var data = make_array();

res = http_send_recv3(method:'GET', item:'/web/guest/en/websys/status/configuration.cgi', port:port, exit_on_fail:FALSE);
if (empty_or_null(res) || res[0] !~ '^HTTP/[0-9.]+ 200')
  res = http_send_recv3(method:"GET", item:"/web/user/en/websys/status/system.cgi", port:port, exit_on_fail:FALSE);

var info, pat, item;

# - Model Number
if ("Model Name" >< res[2])
{
  info = strstr(res[2], "Model Name");
  if ('</tr>' >< info)
  {
    info = info - strstr(info, '</tr>');

    # Example:
    #          <td nowrap>IM C2010</td>
    pat = '^\\s*<td nowrap(?:="nowrap")?>(.+)</td>$';
    foreach var line (split(info, keep:FALSE))
    {
      item = pregmatch(pattern:pat, string:line);
      if (item)
      {
        data['model'] = item[1];
      }
    }
  }
}
if (!max_index(keys(data))) exit(0, "The remote host does not appear to be a Ricoh printer.");

# - Machine ID
if ("Machine ID" >< res[2])
{
  info = strstr(res[2], "Machine ID");
  if ('</tr>' >< info)
  {
    info = info - strstr(info, '</tr>');
    pat = '^[ \t]*<td nowrap(?:="nowrap")?>([A-Z0-9]+)</td>$';
    foreach line (split(info, keep:FALSE))
    {
      item = pregmatch(pattern:pat, string:line);
      if (item)
      {
        data['mid'] = item[1];
      }
    }
  }
}

# - System Version
if ("System" >< res[2])
{
  info = strstr(res[2], "System</td>");
  if ('</tr>' >< info)
  {
    info = info - strstr(info, '</tr>');
    pat = '^[ \t]*<td nowrap(?:="nowrap")?>([0-9]+\\.[0-9.]+)</td>$';
    foreach line (split(info, keep:FALSE))
    {
      item = pregmatch(pattern:pat, string:line);
      if (item)
      {
        data['sysver'] = item[1];
      }
    }
  }
}

# - NIB Version
if ("NIB" >< res[2])
{
  info = strstr(res[2], "NIB");
  if ('</tr>' >< info)
  {
    info = info - strstr(info, '</tr>');
    pat = '^[ \t]*<td nowrap(?:="nowrap")?>([0-9]+\\.[0-9]+)</td>$';
    foreach line (split(info, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:line);
      if (item)
      {
        data['nibver'] = item[1];
      }
    }
  }
}

# - Web Image Monitor Version
if ("Web Image Monitor" >< res[2])
{
  info = strstr(res[2], "Web Image Monitor");
  if ('</tr>' >< info)
  {
    info = info - strstr(info, '</tr>');
    pat = '^[ \t]*<td nowrap(?:="nowrap")?>([0-9]+\\.[0-9]+)</td>$';
    foreach line (split(info, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:line);
      if (item)
      {
        data['wimver'] = item[1];
      }
    }
  }
}

# Update KB and report finding.
replace_kb_item(name:'Services/www/'+port+'/embedded', value:TRUE);
replace_kb_item(name:kb_base, value:TRUE);

var max_label_len = 0;
var label;


info = "";

var val;
var extra = {};

foreach var key (make_list('model', 'mid', 'sysver', 'nibver', 'wimver'))
{
  if (val = data[key])
  {
    replace_kb_item(name:kb_base+'/'+key, value:val);

    label = labels[key];
    extra[label] = val;
  }
}

register_install(
  app_name : 'Ricoh printer',
  vendor   : 'Ricoh',
  product  : 'printer',
  path     : '/',
  version  : data['sysver'],
  port     : port,
  cpe      : 'cpe:/h:ricoh:' + data['model'],
  webapp   : TRUE,
  extra    : extra
);

report_installs(app_name:'Ricoh printer', port:port);
