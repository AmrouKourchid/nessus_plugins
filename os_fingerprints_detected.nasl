#%NASL_MIN_LEVEL 80900
include("compat.inc");

if (description)
{
  script_id(209654);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/03");

  script_name(english:"OS Fingerprints Detected");

  script_set_attribute(attribute:"synopsis", value:
"Multiple OS fingerprints were detected.");
  script_set_attribute(attribute:"description", value:
"Using a combination of remote probes (TCP/IP, SMB, HTTP, NTP, SNMP, etc), 
it was possible to gather one or more fingerprints from the remote system. 
While the highest-confidence result was reported in plugin 11936, “OS Identification”, 
the complete set of fingerprints detected are reported here.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("os_fingerprint.nasl");

  exit(0);
}

include('agent.inc');
include('asset_attribute_normalization_library.inc');
include('os_fingerprint_consolidate_fingerprints.inc');

var methods, OS_kbs;

methods = make_list();

OS_kbs = get_kb_list_or_exit("Host/OS/*");

function get_kb_host_os_item( )
{
  return OS_kbs[_FCT_ANON_ARGS[0]];
}

var matches;

foreach var kb_name (keys(OS_kbs))
{
  matches = pregmatch(pattern:"Host/OS/(\w+)", string:kb_name);
  if (isnull(matches)) continue;

  methods = make_list(methods, matches[1]);
}

methods = list_uniq(methods);

var not_windows = get_kb_item("SMB/not_windows");

var report, kb, confidence_score, type, ret, fingerprint_kb, fingerprint;
var normalized_value, consolidated_os,lc_os;
var method_list = [];
foreach var meth (methods)
{
  kb = get_kb_host_os_item("Host/OS/" + meth);
  if( kb )
  {
    ret = '' ;
    if("Windows" >< kb && not_windows) continue;

    confidence_score = get_kb_host_os_item("Host/OS/" + meth + "/Confidence");
    if ( isnull(confidence_score) ) continue;

    type = get_kb_host_os_item("Host/OS/" + meth + "/Type");
    
    fingerprint_kb = get_kb_host_os_item("Host/OS/" + meth + "/Fingerprint");
    # Add the method for fingerprint found to the list, that we will later loop over to check for missing fingerprints
    append_element(value:meth , var: method_list);
    
    if ( fingerprint_kb )
    {
      if ( get_kb_host_os_item("Host/OS/" + meth) )
        ret += meth + ':' + fingerprint_kb + '\n';
      else
        ret += meth + ':!:' + fingerprint_kb + '\n';
    }
    else
    {
      ret = 'unknown\n';
    }

    fingerprint = ret;

    var unix_agent = FALSE;
    if (agent_unix()) unix_agent = TRUE;

    # Normalize the OS
    #  - Only credentialed / Agents scans are currently supported.
    lc_os = tolower(kb);
    if ( agent_windows() || meth == 'SMB_OS' || (meth == 'Misc' && 'Windows 11' >< kb) )
    {
      normalized_value = asset_attribute_operating_system::normalize(input_value:kb, platform:'WINDOWS');
      dbg::detailed_log(lvl:2, msg:'normalized Windows OS: ' + normalized_value);
    }
    else if ( agent_unix() || 'linux kernel' >< lc_os || 'mac os x' >< lc_os )
    {
      if ((meth == 'LinuxDistribution' || meth == 'SSH' || meth == 'uname' || meth == 'MLSinFP' ) && 'mac os x' >< lc_os )
      {
        # Note that MLSinFP results also normalized for Mac 
        normalized_value = asset_attribute_operating_system::normalize(input_value:kb, platform:'DARWIN');
        dbg::detailed_log(lvl:2, msg:'normalized macOS: ' + normalized_value);
      }
      else
      {
        # Handle Linux
        if ( meth == 'LinuxDistribution' || meth == 'SSH' || meth == 'uname' )
        {
          normalized_value = asset_attribute_operating_system::normalize(input_value:kb, platform:'LINUX');
          dbg::detailed_log(lvl:2, msg:'normalized linux OS: ' + normalized_value);
        }
        else
        {
          dbg::detailed_log(lvl:2, msg:'Host normalization error : No match for os: ' + kb);
        }
      }
    }

    ##
    #  Prevent Linux/macOS normalization changes from changing plugin output
    ##
    if ( !empty_or_null(normalized_value) && ( "windows" >< tolower(kb) || "microsoft" >< tolower(kb) || "hyper-v" >< tolower(kb) ) )
    {
      consolidated_os = consolidate_similar_os_version_strings(os_string:normalized_value);
    }
    else
    {
      consolidated_os = consolidate_similar_os_version_strings(os_string:kb);
    }

    report = strcat(report,
    '\nRemote operating system : ', consolidated_os,
    '\nConfidence level : ', confidence_score,
    '\nMethod : ' + meth,
    '\nType : ' + type,
    '\nFingerprint : ' + fingerprint
    );

  }
}
# Check if there are fingerprints that were not linked to anything due to confidence level
var possible_ret;
foreach meth (methods)
{
  # If the method is in the list , it means the fingerpritn was already checked an reported.
  if (contains_element(var:method_list, value:meth)) continue;

  kb = get_kb_host_os_item("Host/OS/" + meth + "/Fingerprint");
  if ( kb )
  {
    if ( get_kb_host_os_item("Host/OS/" + meth) )
      possible_ret += meth + ':' + kb + '\n';
    else
      possible_ret += meth + ':!:' + kb + '\n';
  }
}

if (!empty_or_null(possible_ret))
{
  report = strcat(report, 
    '\nFollowing fingerprints could not be used to determine OS : ',
    '\n ' + possible_ret);
}

if (!empty_or_null(report)) 
{
  report = strcat('\nFollowing OS Fingerprints were found\n' , report);
  security_note(port:0, extra:report);
}