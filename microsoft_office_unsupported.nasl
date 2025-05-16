#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56998);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/22");
  script_xref(name:"IAVA", value:"0001-A-0503");
  script_name(english:"Microsoft Office Unsupported Version Detection");
  script_summary(english:"Checks Microsoft Office Version");
  script_set_attribute(attribute:"synopsis", value:"The remote host contains an unsupported version of Microsoft Office.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Microsoft Office on the
remote Windows host is no longer supported.
Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us");
  script_set_attribute(attribute:"solution", value:"Upgrade to a version of Microsoft Office that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:'cvss_score_source', value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/02");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("office_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  exit(0);
}
include("smb_hotfixes.inc");


var installs = get_kb_list_or_exit("SMB/Office/*/SP");

var comps, pat, comp, kb_count, comps2013_count, infopath_count, sharepointdesigner_count;
# InfoPath is an Office 2013 component, but is still supported until July 14, 2026
# If Infopath is the ONLY 2013 component, we don't want to flag it

var only_infopath = FALSE;
var sharepointdesigner_extended_support = FALSE;

var comps2013 = get_kb_list('SMB/Office/*/2013/*');
var components_dbg = [];

if (!empty_or_null(comps2013) && len(comps2013) == 1 && 'infopath' >< tolower(keys(comps2013)))
{
  only_infopath = TRUE;
  components_dbg['single_component_infopath -- first check'] = only_infopath;
}
else
{
  only_infopath = FALSE;
  components_dbg['single_component_infopath -- second check'] = only_infopath;
  components_dbg['executed::multiple_components_checks'] = "TRUE";
  comps = get_kb_list('SMB/Office/*');
  comps2013_count = 0;
  
  infopath_count = 0;
  sharepointdesigner_count = 0;
  
  pat = "SMB\/Office\/.+\/15\..+";
  
  foreach comp (keys(comps))
  {
    if (comp =~ pat)
    {
      comps2013_count++;
      if ('infopath' >< tolower(comp))
      {
        infopath_count++;
        components_dbg['infopath_component_count'] = infopath_count;
        components_dbg['infopath_filtered_components'] = [tolower(comp)];
      }
      if ('sharepointdesigner' >< tolower(comp))
      {
        sharepointdesigner_count++;
        sharepointdesigner_extended_support = TRUE;
        components_dbg['sharepointdesigner_component_count'] = sharepointdesigner_count;
        components_dbg['sharepointdesigner_extended_support'] = sharepointdesigner_extended_support;
        components_dbg['sharepointdesigner_filtered_components'] = [tolower(comp)];
        set_kb_item(name:"Microsoft/SharePointDesigner/Extended Support", value:sharepointdesigner_extended_support);
      } 
    }
  }
  if (comps2013_count >= 1 && comps2013_count == infopath_count)
  {
    only_infopath = TRUE;
    components_dbg['single_component_infopath -- third check'] = only_infopath;
  }
  dbg::detailed_log(lvl:1,msg: 'Components checks [LOGS]: ' + '\n' + obj_rep(components_dbg));
}


# nb: office_installed.nasl doesn't support versions before Office 2000 but
#     we'll include some older versions here just in case that changes.
var eos_dates = make_array(
  '2013', 'April 11, 2023',
  '2010', 'October 13, 2020',
  '2007', 'October 10, 2017',
  '2003', 'April 8, 2014',
  'XP',   'July 12, 2011',
  '2000', 'July 14, 2009',
  '97',   'February 28, 2002'
);

var n_eos, n_tot, report, install;

n_eos = n_tot = 0;
report = '';

foreach install (sort(keys(installs)))
{
  install = install - 'SMB/Office/';
  install = install - '/SP';
  n_tot++;
  if (eos_dates[install])
  {
    if (install == '2013' && only_infopath == TRUE || install == '2013' && sharepointdesigner_extended_support == TRUE)
    {
      continue;
    }
    else
    {
      register_unsupported_product(product_name:"Microsoft Office",
                                  cpe_base:"microsoft:office", version:tolower(install));
      n_eos++;
      report +=
        '\n  Installed product   : Office ' + install +
        '\n  End of support date : ' + eos_dates[install] +
        '\n';
    }
  }
}
var port, msg, infopath_msg, o_ver, sp;
if (report)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  if (n_eos == 1) report = chomp(report);
  report += '\n  Supported versions  : Office 2016, 2019, 2021 or Office 365\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else
{
  msg = '';
  foreach o_ver (keys(installs))
  {
    sp = installs[o_ver];
    o_ver = o_ver - 'SMB/Office/';
    o_ver = o_ver - '/SP';
    if (strlen(msg))
      msg += '- Microsoft Office'  + o_ver + ' SP ' + sp + '\n';
    else
      msg = '- Microsoft Office ' + o_ver + ' SP ' + sp + '\n';
  }
  
  msg = 'The following supported installs of Microsoft Office are present : \n' + msg;
  
  if (only_infopath == TRUE)
  {
    msg += '\nNote: For Microsoft Office 2013, Infopath is the only component present and is still supported.';
  }
    
  if (sharepointdesigner_extended_support == TRUE)
  {
    msg += '\nNote: For Microsoft Office 2013, SharePointDesigner component is present and is still supported.';
  }
  exit(0, msg);
}
