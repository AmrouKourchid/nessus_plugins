#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#

# @@NOTE: The output of this plugin should not be changed
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(11936);
  script_version("2.73");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_name(english:"OS Identification");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to guess the remote operating system.");
  script_set_attribute(attribute:"description", value:
"Using a combination of remote probes (e.g., TCP/IP, SMB, HTTP, NTP,
SNMP, etc.), it is possible to guess the name of the remote operating
system in use. It is also possible sometimes to guess the version of
the operating system.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/12/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2004-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies(
    "os_fingerprint_http.nasl",
    "os_fingerprint_html.nasl",
    "os_fingerprint_ldap.nasl",
    "os_fingerprint_mdns.nasl",
    "os_fingerprint_misc.nasl",
    "os_fingerprint_ntp.nasl",
    "os_fingerprint_sinfp.nasl",
    "os_fingerprint_sip.nasl",
    "os_fingerprint_smb.nasl",
    "os_fingerprint_smtp.nasl",
    "os_fingerprint_snmp.nasl",
    "os_fingerprint_snmp_sysobjectid.nasl",
    "os_fingerprint_snmp_software.nasl",
    "os_fingerprint_sslcert.nasl",
    "os_fingerprint_ftp.nasl",
    "os_fingerprint_xprobe.nasl",
    "os_fingerprint_msrprc.nasl",
    "os_fingerprint_uname.nasl",
    "os_fingerprint_ssh.nasl",
    "os_fingerprint_linux_distro.nasl",
    "os_fingerprint_telnet.nasl",
    "os_fingerprint_upnp.nbin",
    "os_fingerprint_afp.nasl",
    "os_fingerprint_ethernet.nasl",
    "os_fingerprint_hnap.nasl",
    "barco_wepresent_detect.nbin",
    "cisco_gss_version.nasl",
    "cisco_ios_version.nasl",
    "cisco_ios_xe_version.nasl",
    "cisco_ios_xr_version.nasl",
    "cisco_nxos_version.nasl",
    "cisco_esa_version.nasl",
    "cisco_sma_version.nasl",
    "cisco_wsa_version.nasl",
    "lockdown_detect.nasl",
    "ilo_detect.nasl",
    "os_fingerprint_nativelanmanager.nasl",
    "os_fingerprint_ssh_netconf.nasl",
    "os_fingerprint_rdp.nbin",
    "ibmi_detect.nbin",
    "symantec_management_center_web_detect.nbin",
    "pfsense_webui_detect.nbin",
    "os_fingerprint_ios.nasl",
    "os_fingerprint_airplay.nasl",
    "os_fingerprint_ml_sinfp.nbin",
    "ibm_tem_init_info.nbin"
  );
  exit(0);
}

include('agent.inc');
include('asset_attribute_normalization_library.inc');
include('os_fingerprint_consolidate_fingerprints.inc');
include('os_install.inc');
include('json2.inc');

# Dynamically makes fingerprint method list
# We need both once with Confidence and Fingerprints,
# so it will be best to just grab everything.
var methods, OS_kbs;

methods = make_list();

OS_kbs = get_kb_list_or_exit("Host/OS/*");

##
# Get a single item from the kb without forking.
#
# With the regular 'get_kb_item()' function, the script will fork, potentially causing unexpected behaviour.
#
# @anonparam key The exact key whose value you wish to retrieve.
#
# @return string The exact string of the value matching the key. NULL if nothing found.
##
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

##
# Get the OS fingerprint with the highest confidence level and the string length.
#
# @return [array] OS fingerprint details (keys: 'os', 'meth', 'confidence', 'type') if successful
#         NULL otherwise 
##
function get_best_match()
{
 local_var meth;
 local_var best_match;
 local_var best_score;
 local_var best_type;
 local_var best_meth;
 local_var best_meth1;
 local_var kb;
 local_var score;
 local_var ret;
 local_var len, len2;
 local_var kb_confidence;
 local_var type;

 local_var not_windows = get_kb_item("SMB/not_windows");

 foreach meth (methods)
 {
  kb = get_kb_host_os_item("Host/OS/" + meth);
  if( kb )
  {
   if("Windows" >< kb && not_windows) continue;

   score = get_kb_host_os_item("Host/OS/" + meth + "/Confidence");
   if ( isnull(score) ) continue;

   type = get_kb_host_os_item("Host/OS/" + meth + "/Type");

   if ( score < best_score ) continue;

   # Choose any other method over SinFP if confidence levels are the same
   if ( score == best_score )
   {
    if ( meth == 'SinFP' ) continue;
   }

   best_score = score;
   best_meth  = meth;
   best_match  = kb;
   best_type  = type;
  }
 }

 if (isnull(best_meth))  return NULL;

 # Try to find something more precise
 best_meth1 = best_meth;
 len = strlen(best_match);
 foreach meth (methods)
   if (meth != best_meth)
   {
     kb = get_kb_host_os_item("Host/OS/" + meth);
     if (kb)
     {
       if ( '\n' >< kb ) continue;
       kb_confidence = get_kb_host_os_item("Host/OS/" + meth + "/Confidence");
       len2 = strlen(kb);
       if(len2 > len && kb_confidence >= 80 && best_match >< kb )
       {
         len = len2;
         score = kb_confidence;
         # best_score = score;
         best_meth  = meth;
         best_match  = kb;
         best_type  = get_kb_host_os_item("Host/OS/" + meth + "/Type");
       }
     }
   }

  ret["meth"] = best_meth;
  if (best_meth != best_meth1) ret["meth1"] = best_meth1;
  ret["confidence"] = best_score;
  ret["os"] = best_match;
  ret["type"] = best_type;

  # Add port and protocol, mainly for register_os().
  var best_protocol = get_kb_host_os_item(strcat('Host/OS/', best_meth, '/Protocol'));
  var best_port = get_kb_host_os_item(strcat('Host/OS/', best_meth, '/Port'));

  # Remote detection
  if (!empty_or_null(best_port))
  {
    ret['detection_type'] = 'remote';
    ret['port'] = best_port;

    if (!empty_or_null(best_protocol) || best_protocol !~ '^(tcp|udp)$')
      ret['protocol'] = best_protocol;
    else
      ret['protocol'] = 'tcp';
  }
  # Local detection
  else
  {
    ret['detection_type'] = 'local';
  }

  return ret;
}

##
# Get the OS fingerprints for reporting.
#
# @return [str] a compiled string of the OS fingerprints
## 
function get_fingerprint()
{
 local_var meth;
 local_var ret;
 local_var kb;

 foreach meth ( methods )
 {
  kb = get_kb_host_os_item("Host/OS/" + meth + "/Fingerprint");
  if ( kb )
  {
    if ( get_kb_host_os_item("Host/OS/" + meth) )
     ret += meth + ':' + kb + '\n';
    else
     ret += meth + ':!:' + kb + '\n';
  }
 }
 return ret;
}

##
# Determine whether OS fingerprints exist for any method excluding certain methods.
#
# @remark Checks the '/Fingerprint' KB item
# @remark Excludes certain methods: ICMP, Misc, SSH, telnet, SSLcert
#
# @return [bool] 1 if a missing OS fingerprint was found
#                0 otherwise
##
function missing_fingerprints()
{
 local_var meth;
 local_var flag;

 flag = 0;
 foreach meth ( methods )
 {
  if ( meth == "HTTP" || meth == "ICMP" || meth == "Misc" || meth == "SSH" || meth == "telnet" || meth == "SSLcert" ) continue;
  if ( get_kb_host_os_item("Host/OS/" + meth + "/Fingerprint") &&
      !get_kb_host_os_item("Host/OS/" + meth) )  flag ++;
 }

 if ( flag ) return 1;
 else return 0;
}


##
# Register the OS if not already registered.
#
# @param  [metadata:array ref]     detection metadata (e.g. detection type, protocol, port)
# @param  [os_details:array ref]   OS details (e.g. vendor, os, version, edition)
# @param  [normalizer:object ref]  asset_attribute_operating_system::normalizer object with normalized attributes (e.g. vendor, os)
#
# @remark The "os_details" and "normalizer" contain very similar attributes but there 
#
# @return [boolean] true if OS was registered
#                   false otherwise
##
function register_os_fingerprint(&metadata, &os_details, &normalizer)
{
  # Require both os_details and normalizer
  if (empty_or_null(metadata) || empty_or_null(os_details) || empty_or_null(normalizer))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'The OS was not registered because one of the required arguments is empty or null.');
    return false;
  }

  # Skip local detections for now, since they should be registered already and there is a possibility of duplicate registrations.
  #  - For example, the OS is registered with the "SSH" method but then the "uname" and "LinuxDistribution" methods could trigger.
  if (metadata.detection_type == 'local')
  {
    dbg::detailed_log(lvl:4, src:FUNCTION_NAME, msg:'Skipping local detection type with method ' + os_details.method);
    return false;
  }

  # Skip MLSinFP
  if (os_details.method == 'MLSinFP')
    return false;

  dbg::detailed_log(lvl:4, src:FUNCTION_NAME, msg:'normalizer', msg_details:{value:{lvl:4, value:normalizer}});

  # For multiple detections with the same type and method, check to see if we registered the OS info
  # in this plugin to allow for subsequent OS info to be registered and bypass the check below.
  var os_registered_in_this_plugin = false;
  var os_info;

  foreach os_info (os_install::InstallObjects['operating-system'])
  {
    if (os_info.type == metadata.detection_type && os_info.method == os_details.method)
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:vsprintf(format:
        'OS was registered earlier in this plugin with type "%s" and method "%s"', args: [ metadata.detection_type, os_details.method ])
      );

      os_registered_in_this_plugin = true;
      break;
    }
  }

  # If this OS info was not already registered, check that the OS wasn't already registered in a downstream plugin.
  if (!os_registered_in_this_plugin)
  {
    os_info = get_os(type: metadata.detection_type, method: os_details.method, branch:false, exit_if_not_found:false);
    if (!empty_or_null(os_info))
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:vsprintf(format:
        'OS has already been registered with type "%s" and method "%s"', args: [ metadata.detection_type, os_details.method ])
      );

      return false;
    }
  }

  # Gather OS attributes
  var type       = metadata.detection_type;
  var protocol   = metadata.protocol;
  var port       = metadata.port;

  var method     = os_details.method;
  var confidence = os_details.confidence;

  var vendor = normalizer.normalized.vendor;
  if (empty_or_null(vendor))
    vendor = os_details.vendor;

  var product = normalizer.normalized.os;
  if (empty_or_null(product))
    product = normalizer.normalized.distro;
  if (empty_or_null(product))
    product = os_details.distribution;

  var release = normalizer.normalized.release;
  
  var version = normalizer.normalized.version;
  if (empty_or_null(version))
    version = release;

  var edition = normalizer.normalized.edition;
  if (empty_or_null(edition))
    edition = normalizer.normalized.codename;

  var os_name = os_details.normalized_os;

  var kernel = normalizer.normalized.kernel;
  var kernel_version;

  if (empty_or_null(kernel))
  {
    kernel = normalizer.normalized.linux_kernel_string;

    kernel_version = normalizer.normalized.linux_kernel;
    if (!empty_or_null(kernel_version))
      kernel += ' ' + kernel_version;
  }

  var cpe = os_details.cpev23;

  # Register OS attributes
  register_os(

    type        : type,
    method      : method,
    confidence  : confidence,

    protocol    : protocol,
    port        : port,

    vendor      : vendor,
    product     : product,
    version     : version,
    release     : release,
    os_edition  : edition,

    os_name     : os_name,
    kernel      : kernel,
    cpe         : cpe

  );
}


##
# Main
##
var best, consolidated_os, report, fg, xml_tag, operating_system, os_details, lc_os, vendor, distro, os_match, cpe, metadata;

best = get_best_match();

if ( ! isnull(best) )
{
  var unix_agent = FALSE;
  if (agent_unix()) unix_agent = TRUE;

  replace_kb_item(name: "Host/normalization/original_os", value: best['os']);

  # Split up potentially multiple remote detections
  #  - Example: Linux Kernel 2.6 on Fedora release 10\nLinux Kernel 2.6 on Fedora release 11
  var oses = split(best['os'], sep:'\n', keep:FALSE);
  var os, normalized_value;

  foreach os (oses)
  {
    # Normalize the OS
    #  - Only credentialed / Agents scans are currently supported for Windows.
    #  - Local and remote scans are supported for Linux/Unix-based OSes.
    lc_os = tolower(os);

    if ( agent_windows() ||
        best['meth'] == 'SMB_OS' ||
        (best['meth'] == 'Misc' && 'Windows 11' >< os) )
    {
      # Handle Windows
      distro = 'Windows';
      cpe = "cpe:2.3:o:microsoft:windows";

      normalized_value = asset_attribute_operating_system::normalize(input_value:os, platform:'WINDOWS');
      dbg::detailed_log(lvl:2, msg:'normalized Windows OS: ' + normalized_value);
    }
    else if ( agent_unix() ||
              'linux kernel' >< lc_os ||
              'mac os x' >< lc_os
            )
    {
      if (
        'mac os x' >< lc_os && (
          best['meth'] == 'LinuxDistribution' ||
          best['meth'] == 'SSH'     ||
          best['meth'] == 'uname'   ||
          best['meth'] == 'HTTP'    ||
          best['meth'] == 'MLSinFP' || 
          best['meth'] == 'SNMP' 
        )
      )
      {
        # Handle Mac
        vendor = 'Apple';
        distro = 'Mac OS X';
        cpe = "cpe:2.3:o:apple:mac_os_x";

        # Note that MLSinFP results also normalized for Mac 
        normalized_value = asset_attribute_operating_system::normalize(input_value:os, platform:'DARWIN');
        dbg::detailed_log(lvl:2, msg:'normalized macOS: ' + normalized_value);

        if ('macOS' >< normalized_value)
          cpe = "cpe:2.3:o:apple:macos";
      }
      else
      {
        # Handle Linux
        if (
          best['meth'] == 'LinuxDistribution' ||
          best['meth'] == 'SSH'   ||
          best['meth'] == 'uname' ||
          best['meth'] == 'FTP'   ||
          best['meth'] == 'HTTP'  ||
          best['meth'] == 'SMTP'  ||
          best['meth'] == 'SNMP'  ||
          best['meth'] == 'telnet'
        )
        {
          normalized_value = asset_attribute_operating_system::normalize(input_value:os, platform:'LINUX');
          dbg::detailed_log(lvl:2, msg:'normalized linux OS: ' + normalized_value);

          # Similar checks present in includes/asset_attribute_operating_system.static
          if ('almalinux' >< lc_os)
          {
            vendor = 'AlmaLinux OS Foundation';
            distro = 'Alma Linux';
            cpe = "cpe:2.3:o:almalinux:almalinux";
          }
          else if ('amazon linux' >< lc_os)
          {
            vendor = 'Amazon Web Services';
            distro = 'Amazon Linux 2';
            cpe = "cpe:2.3:o:amazon:linux_2";
          }
          else if ('centos' >< lc_os)
          {
            vendor = 'The CentOS Project';
            distro = 'CentOS Linux';
            cpe = "cpe:2.3:o:centos:centos";
          }
          else if ('debian' >< lc_os)
          {
            vendor = 'Debian';
            distro = 'Debian Linux';
            cpe = "cpe:2.3:o:debian:debian_linux";
          }
          else if ('fedora' >< lc_os)
          {
            vendor = 'The Fedora Project';
            distro = 'Fedora Linux';
            cpe = "cpe:2.3:o:fedoraproject:fedora";
          }
          else if ('gentoo' >< lc_os)
          {
            vendor = 'Gentoo Foundation';
            distro = 'Gentoo Linux';
            cpe = "cpe:2.3:o:gentoo:linux";
          }
          else if ('red hat' >< lc_os)
          {
            vendor = 'Red Hat';
            distro = 'Red Hat Linux';
            cpe = "cpe:2.3:o:redhat:linux";
          }
          else if ('oracle linux' >< lc_os)
          {
            vendor = 'Oracle';
            distro = 'Oracle Linux';
            cpe = "cpe:2.3:o:oracle:linux";
          }
          else if ('opensuse' >< lc_os)
          {
            vendor = 'OpenSuSE Project';
            distro = 'OpenSuSE Linux';
            cpe = "cpe:2.3:o:suse:opensuse";
          }
          else if ('suse' >< lc_os)
          {
            vendor = 'SUSE';
            distro = 'SuSE Linux';
            cpe = "cpe:2.3:o:suse:suse_linux";
          }
          else if ('sles_sap' >< lc_os)
          {
            vendor = 'SUSE';
            distro = 'SLES for SAP';
            cpe = "cpe:2.3:o:suse:linux_enterprise_module_for_sap_applications";
          }
          else if ('ubuntu' >< lc_os)
          {
            vendor = 'Canonical';
            distro = 'Ubuntu Linux';
            cpe = "cpe:2.3:o:canonical:ubuntu_linux";
          }
        }
        else
        {
          replace_kb_item(name:"Host/normalization/error", value: strcat('No match for os: ', obj_rep(best), '\n'));
        }
      }
    }

    # Collect additional data for registering the OS and "operating-system-details" asset attribute
    if (!empty_or_null(normalized_value))
    {
      replace_kb_item(name: "Host/normalization/normalized_os", value: normalized_value);

      # Detection type metadata
      metadata = {
        detection_type : best.detection_type,
        protocol       : best.protocol,
        port           : best.port
      };

      # Collect data for "os_details" array
      os_details['os'] = os;
      os_details['confidence'] = best['confidence'];
      os_details['type'] = best['type'];
      os_details['method'] = best['meth'];

      os_details['normalized_os'] = normalized_value;
      os_details['vendor'] = vendor;
      os_details['distribution'] = distro;
      os_details['cpev23'] = cpe;

      # get version alone
      os_match = pregmatch(string:normalized_value, pattern:"^.+\s(Linux Server|Linux|OS X|macOS|for SAP)\s(.+)$");
      if (!empty_or_null(os_match[2]))
        os_details['version'] = os_match[2];

      # get kernel alone
      os_match = NULL;      
      os_match = pregmatch(string:best['os'], pattern:"^(.+) on ");
      if (!empty_or_null(os_match[1]))
        os_details['kernel'] = os_match[1];

      # get code/edition if available
      os_match = NULL;
      os_match = pregmatch(string:best['os'], pattern:".+release .+ \((.+)\)$");
      if (!empty_or_null(os_match[1]))
        os_details['code'] = os_match[1];

      # Register the OS fingerprint
      register_os_fingerprint(
        metadata   : metadata,
        os_details : os_details,
        normalizer : asset_attribute_operating_system::normalizer
      );
    }
  }

  ##
  #  Prevent Linux/macOS normalization changes from changing plugin output
  ##
  if ( !empty_or_null(normalized_value) &&
      ( "windows" >< tolower(best['os']) || "microsoft" >< tolower(best['os']) || "hyper-v" >< tolower(best['os']) ) )
  {
    consolidated_os = consolidate_similar_os_version_strings(os_string:normalized_value);
  }
  else
  {
    consolidated_os = consolidate_similar_os_version_strings(os_string:best['os']);
  }

  report = strcat(
    '\nRemote operating system : ', consolidated_os,
    '\nConfidence level : ', best["confidence"],
    '\nMethod : ' + best["meth"] + '\n'
  );
  if (best["meth1"])
    report = strcat(report, '\nPrimary method : ', best["meth1"], '\n');

 if ( missing_fingerprints() )
 {
  fg = get_fingerprint();
  if ( fg ) report +=
    '\n' + 'Not all fingerprints could give a match. If you think that these' +
    '\n' + 'signatures would help us improve OS fingerprinting, please submit' +
    '\n' + 'them by visiting https://www.tenable.com/research/submitsignatures.' +
    '\n' +
    '\n' + fg;
 }

 if ( defined_func("report_xml_tag") )
 {
  # At least for now, replace the legacy macOS formatting with the current expected format
  # All sw_vers response appear as Mac OS X for 10.* and macOS for 11.* onward.
  # Consult RES-101983 for further details.
  xml_tag = best["os"];
  if (preg(pattern:"^Mac OS X ", string:xml_tag))
  {
   if (!preg(pattern:"^Mac OS X 10\.", string:xml_tag))
   {
    xml_tag = ereg_replace(string:xml_tag, pattern:"^Mac OS X ", replace:"macOS ");
   }
   # KB for flatline testing purposes
   replace_kb_item(name:"Flatline/MacOSX/operating-system/os_fingerprint1", value:xml_tag);
  }
  report_xml_tag(tag:"operating-system", value:xml_tag);
  if ( !isnull(best["type"]) ) report_xml_tag(tag:"system-type", value:best["type"]);
 }

 # The text of the plugin output in the following lines must not be modified to avoid breaking SC
 if ( '\n' >!< consolidated_os )
  report += '\n \nThe remote host is running ' + consolidated_os;
 else
  report += '\n \nThe remote host is running one of these operating systems : \n' + consolidated_os;

 security_note(port:0, extra:report);
 operating_system = make_nested_array();
 if ( !isnull(best["os"]) )
 {
   if (!isnull(normalized_value))
   {
     # Use normalized value for
     #  KB and host tag reporting
     operating_system['os'] = normalized_value;
     replace_kb_item(name:"Host/OS", value:normalized_value);
   }
   else
   {
     operating_system['os'] = best['os'];
     replace_kb_item(name:"Host/OS", value:best['os']);
   }
 }
 if ( !isnull(best["confidence"]) )
 {
  replace_kb_item(name:"Host/OS/Confidence", value:best["confidence"]);
  operating_system['confidence_level'] = best["confidence"];
 }
 if ( !isnull(best["type"]) )
 {
  replace_kb_item(name:"Host/OS/Type", value:best["type"]);
 }
 if ( !isnull(best['meth']) )
 {
  replace_kb_item(name:"Host/OS/Method", value:best["meth"]);
  operating_system['method'] = best["meth"];
 }

 if (!empty_or_null(operating_system))
 {
  dbg::detailed_log(lvl:2, msg:'operating-system:\n' + obj_rep(operating_system));
  report_tag_internal(tag:"operating-system", value:operating_system);
 }

 if (!empty_or_null(os_details))
 {
  dbg::detailed_log(lvl:2, msg:'operating-system-details:\n' + obj_rep(os_details));
  report_tag_internal(tag:"operating-system-details", value:json_write(os_details));
 }
 
 exit(0);
}
else if ( missing_fingerprints() )
{
 fg = get_fingerprint();
 if ( fg ) replace_kb_item(name:"Host/OS/Fingerprint/Fail", value:fg);
}

