#%NASL_MIN_LEVEL 80900
include("compat.inc");

if (description)
{
  script_id(198218);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/05");
  script_name(english:"Ubuntu Pro Subscription Detection");
  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host has an active Ubuntu Pro subscription.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu host has an active Ubuntu Pro subscription.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/31");
  script_set_attribute(attribute:"see_also", value:"https://documentation.ubuntu.com/pro/");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");
  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Ubuntu/UA-status");

  exit(0);
}

include('json.inc');
include('install_func.inc');

# Function to build report for machines that are currently attached to Ubuntu Pro subscription
function is_attached(details)
{
  var report;
  
  if (details.attached == 1)
    report = 'This machine is attached to an Ubuntu Pro subscription.\n\n';
  else 
    return not_attached(details:details);

  report += process_details(details:details);
    
  return report;
}

# Function to build report for machines that are NOT currently attached to Ubuntu Pro subscription
function not_attached(details)
{
  var report = exit_msg + 
               ' However, it may have previously been attached.\n\n' +
               'The following details were gathered from /var/lib/ubuntu-advantage/status.json:\n\n';
  report += process_details(details:details);
  return report;
}

# Process the collected details and build the report
function process_details(details)
{
  var report, item, service;
  var service_list = [];

  if (!empty_or_null(details.pro_type))
    report += 'Subscription Contract Type   : ' + details.pro_type + '\n';
  if (!empty_or_null(details.pro_path))
    report += 'Binary Path                  : ' + details.pro_path + '\n';
  if (!empty_or_null(details.pro_version))
    report += 'Binary Version               : ' + details.pro_version + '\n';

  # Only enumerate enabled services if attached
  if (!empty_or_null(details.pro_services) && !empty_or_null(details.attached))
  {
    foreach item (details.pro_services)
    {
      if (item.entitled == 'yes' && item.status == 'enabled')
      {
        append_element(value:'  - ' + item.name + '\n' , var:service_list );
        replace_kb_item(name:'Host/Ubuntu/Pro/Services/' + item.name, value:1);
      }
    }

    if (max_index(service_list) > 0)
    {
      report += '\nEnabled Ubuntu Pro Services  :\n';
      foreach service (service_list)
      {
        report += service;
      }
    }
  }
  return report;
}

var app_name = 'Ubuntu Pro';
var exit_msg = 'This machine is NOT attached to an Ubuntu Pro subscription.';
var json_status = get_kb_item_or_exit('Host/Ubuntu/UA-status', msg:exit_msg);
                    
var read_json = json_read(json_status);
read_json = read_json[0];

var pro_details = {};
pro_details.attached = read_json.attached;
pro_details.pro_version = read_json.version;
pro_details.pro_services = read_json.services;
pro_details.pro_type = read_json.contract.name; 
pro_details.pro_path = read_json.config.data_dir;

var report = is_attached(details:pro_details);

security_report_v4(
  port      : 0,
  severity  : SECURITY_NOTE, 
  extra     : report
);

