#TRUSTED 3f1f1faa843772cf2fa78d7c2a973fed1eea66685dd90403e8e59e629cd33d6df0a6c1c768998cfb298578b47782264f55b2ccd3cc8d3a974fd62be2619e72f502641e0d0acfacb5d8a2590e73eecd71149fe0b770c877ea7d486616ee079a6bb5f88081cb9502e103d7369f2d05cfbe76b626b70c9fb60740de417349901133c6a1c5bcc911e280b6b86de3325bf8f43895e7ef08cdf30698b78aa2448fd0fdaa0a9897d814d381f57ab1ff5cafc403ff69d0c8c857160daae56576a6bcedc35dc0316875166de5534c2037f38e70445c740c392921382d521d51bbb85e784fc4a4e9fa699fae8cc2a467127380bc4ef522c1189861668b6cb769fe38ef126ef399b818e17afe92a59d4006ed76c0d16af1380fc0690e8522c54a22361400e16e1039897644fd455c9a5756b0f0a78ed794c635797266a3a4361e765ebfbab98533450c6b1728f525651034b846a2f73f7d8c6087c28b3e206230816fd94bba45aa1acdb7d8aa29bfb7b06ea4e6ebb67d87f6b323b937170e2229c911aecf24b67b6feb934938f1341c7d2fcf42c5ee44f83ff25fd996cbee0eb46d968bcf6d54765c9427c3f8ea6054645ad388b7b03bebbd54417e2c25baca01c84be90aed92987dfe2c73fc9d379bee52e383dc7f3ed3cfcad88e67136c16c7053b81b736f120bac7ee1aecb86230592a1190e4226dc5f688eef58e0c84e554393926b846
#TRUST-RSA-SHA256 a0528b2242631c815da64339b58a2f494ea20f4be23868d08a4649e0af4b21de3fa664163f7a1a7c09454e3108b367e410a76be2b5361963af21dfa978eaab4191121523ba53ed26fee61a6bc8fe1d680714e2b3e6e5dedc281434102217623c9576c50e34d903e7d3c7e166d26e4cc7ceb6a3cdc4b3666af0ab41c4a1ce591b86278a481b046512ecfa2a17dd8a781339f415f685e1ebcd804c8401e0f82f56b3261381c1763f9337b3b076c86e0de6455568301977465fae680f1c741bb044501bf99a0ad2d1dd46c302d827adc3dc32c0956e04f75996253804e5c43c5d25cef9f0230cd246adce17b26090377da50a8c0933a2828eba71d41a15e5099c3ec417691a6fac6e88ebe6d326e85c690c91075fdfe010ad938949556918787782eeb5f67cdf4c74fe2de8255da5786424060a38a0f380e1c3f13d596d75745b7d388ddd77c033cb4be9bdbe3f8f0f4825a49a5768090f35bd1c5b660ffd2c18231794df2b427bc9644f660ccd92a7ab8c6bfd995ad76b1e4426f9ac8a32d1d955cc976977ad773862255ba87f58058fbc5f645504826b629373f6df97793adb69282efcaa812b6d704373dc04189389e8d504dbc4e29fd669882aca0d0e23b2577008e94d719e0fd1eb274c4ab8556bcd7ce1c17ee2d8d327ed5b221130bf4ac5adfdddbdeb7c25ff5325feba490c907cbd13586c5ea66769619055114f24bda8
#
# Revision: 1.89
#

global_var report;

include("compat_shared.inc");
include("byte_func.inc");
include("ssh_lib.inc");
include("agent.inc");
include("spad_log_func.inc");
include("cisco_device_types.inc");
include("ssh_func.inc");
include("vcf.inc");
include("resolv_func.inc");
include('os_install.inc');
include('structured_data.inc');
include('hardware_registration.inc');
include('host_os.inc');

#pragma static(include)
include("ssh_get_info2.static");
include("ssh_get_info2_nix.static");
include("ssh_get_info2_linux.static");
include("ssh_get_info2_gentoo.static");
include("ssh_get_info2_slackware.static");
include("ssh_get_info2_montavista.static");
include("ssh_get_info2_rhel.static");
include("ssh_get_info2_centos.static");
include("ssh_get_info2_timos.static");
include("ssh_get_info2_amazonlinux.static");
include("ssh_get_info2_fedora.static");
include("ssh_get_info2_scientific_linux.static");
include("ssh_get_info2_oracle_linux.static");
include("ssh_get_info2_oracle_vm.static");
include("ssh_get_info2_virtuozzo_linux.static");
include("ssh_get_info2_euleros.static");
include("ssh_get_info2_suse.static");
include("ssh_get_info2_debian.static");
include("ssh_get_info2_kylin_os.static");
include("ssh_get_info2_hpux.static");
include("ssh_get_info2_container_linux.static");
include("ssh_get_info2_aix.static");
include("ssh_get_info2_exos.static");
include("ssh_get_info2_freebsd.static");
include("ssh_get_info2_netbsd.static");
include("ssh_get_info2_solaris.static");
include("ssh_get_info2_mac.static");
include("ssh_get_info2_f5_bigip.static");
include("ssh_get_info2_f5_bigip_bash.static");
include("ssh_get_info2_cisco_ios.static");
include("ssh_get_info2_cisco_ios_xr.static");
include("ssh_get_info2_nxos.static");
include("ssh_get_info2_windows.static");
include("ssh_get_info2_openbsd.static");
include("ssh_get_info2_cisco_asa.static");
include("ssh_get_info2_cisco_asa_cx.static");
include("ssh_get_info2_cisco.static");
include("ssh_get_info2_cisco_aci.static");
include("ssh_get_info2_photon_os.static");
include("ssh_get_info2_netapp.static");
include("ssh_get_info2_rios.static");
include("ssh_get_info2_cisco_firepower.static");
include("ssh_get_info2_cisco_firepower_alt1.static");
include("ssh_get_info2_cisco_firepower_common.static");
include("ssh_get_info2_zscaleros.static");
include("ssh_get_info2_windriverlinux.static");
include("ssh_get_info2_symantec_cas.static");
include("ssh_get_info2_zte_cgsl.static");
include("ssh_get_info2_cisco_ucos.static");
include("ssh_get_info2_rancher_os.static");
include("ssh_get_info2_cisco_ise.static");
include("ssh_get_info2_arista_eos.static");
include("ssh_get_info2_cisco_fmc.static");
include("ssh_get_info2_checkpoint_gaia.static");
include("ssh_get_info2_mcafee.static");
include("ssh_get_info2_fortios.static");
include("ssh_get_info2_cisco_viptela.static");
include("ssh_get_info2_mobileiron.static");
include("ssh_get_info2_zyxel_usg.static");
include("ssh_get_info2_zyxel_device.static");
include("ssh_get_info2_teltonika_rutos.static");
include("ssh_get_info2_zxrosng.static");
include("ssh_get_info2_citrix_adc.static");
include("ssh_get_info2_citrix_adc_sdx.static");
include("ssh_get_info2_citrix_ns.static");
include("ssh_get_info2_aruba.static");
include("ssh_get_info2_citrix_adm.static");
include("ssh_get_info2_panos.static");
include("ssh_get_info2_bluecoat_proxysg.static");
include("ssh_get_info2_fireeye.static");
include("ssh_get_info2_huawei_vrp.static");
include("ssh_get_info2_cisco_cimc.static");
include("ssh_get_info2_rpm_generic.static");
include("ssh_get_info2_arista_eos_ios.static");
include("ssh_get_info2_qnap_standard.static");
include("ssh_get_info2_qnap_qes.static");
include("ssh_get_info2_acos.static");
include("ssh_get_info2_adtran.static");
include("ssh_get_info2_sophos_utm.static");
include("ssh_get_info2_vmware_esxi.static");
include("ssh_get_info2_cisco_adeos.static");
include("ssh_get_info2_fabricos.static");
include("ssh_get_info2_cisco_asyncos.static");
include("ssh_get_info2_vmware_nsx.static");
include("ssh_get_info2_cisco_csp.static");
include("ssh_get_info2_cisco_ips.static");
include("ssh_get_info2_cisco_ip_phone.static");
include("ssh_get_info2_cisco_nam.static");
include("ssh_get_info2_cisco_staros.static");
include("ssh_get_info2_citrix_xen.static");
include("ssh_get_info2_cisco_telepresence_vcs.static");
include("ssh_get_info2_cisco_ucs_director.static");
include("ssh_get_info2_ibm_storwize.static");
include("ssh_get_info2_emc_dell_os10.static");
include("ssh_get_info2_mcafee_secureos.static");
include("ssh_get_info2_ivanti_sentry.static");
include("ssh_get_info2_juniper_space.static");
include("ssh_get_info2_mandriva_linux.static");
include("ssh_get_info2_juniper_screenos.static");
include("ssh_get_info2_forcepoint_sg.static");
include("ssh_get_info2_cisco_catalyst_center.static");
include("ssh_get_info2_ubiquiti.static");
include("ssh_get_info2_trendmicro_iwsva.static");
include("ssh_get_info2_tencentos.static");
include("ssh_get_info2_oracle_sbc.static");
include("ssh_get_info2_infoblox_nios.static");
include("ssh_get_info2_aruba_cppm.static");
include("ssh_get_info2_forescout_counteract.static");
include("ssh_get_info2_azure_linux.static");
include("ssh_get_info2_extreme_networks_fabric_engine.static");
include("ssh_get_info2_dell_idrac.static");
include("ssh_get_info2_arrayos.static");
#pragma static(include:false)
include("lcx.inc");
include("ssh_globals.inc");
include("debug.inc");
include("hostlevel_funcs.inc");

# list of shell handlers to try in order of commonality
global_var handler_list = make_list(
  "sshlib::sh_shell_handler",
  "sshlib::tmsh_shell_handler",
  "sshlib::aruba_s_shell_handler", # Aruba devices have a press any key to continue prompt, it's important to handle this one early in the list.
  "sshlib::panos_shell_handler", # Handle PAN-OS devices early because they provide limited info for pre-checks and are inactive in response to exec requests
  "sshlib::netapp_shell_handler", # Do NetApp early because paged error messages about unknown commands will cause shell handler timeouts
  "sshlib::ios_shell_handler",
  "sshlib::huawei_vrp_shell_handler",
  "sshlib::timos_shell_handler",
  "sshlib::exos_shell_handler",
  "sshlib::cisco_ucos_shell_handler",
  "sshlib::cisco_adeos_shell_handler",
  "sshlib::forescout_counteract_shell_handler", # CounterACT shell handler needs to run prior to fortio_shell_handler to avoid a timeout
  "sshlib::fortios_shell_handler",
  "sshlib::cisco_viptela_shell_handler",
  "sshlib::citrix_adm_shell_handler",
  "sshlib::qnap_standard_shell_handler",
  "sshlib::qnap_standard_qes_handler",
  "sshlib::basic_shell_handler"
);

global_var start_time;

global_var linux_check = {'pre_check_fail_cb' : @linux_pre_check_fail,
               'test_cmd'          : 'uname -a',
               'test_cmd_regex'    : "^Linux\s",
               'cmd_success_cb'    : @handle_linux_os,
               'cmd_fail_cb'       : @handle_not_linux_os};

global_var openbsd_check = {'pre_check_fail_cb' : @openbsd_pre_check_fail,
                'test_cmd'           : 'uname -a',
                'test_cmd_regex'     : "^OpenBSD\s",
                'cmd_success_cb'     : @handle_openbsd,
                'cmd_fail_cb'        : @handle_not_openbsd};

global_var mac_check = {'pre_check_fail_cb' : @mac_pre_check_fail,
             'test_cmd'          : 'uname -a',
             'test_cmd_regex'    : "^Darwin\s",
             'cmd_success_cb'    : @handle_mac_os,
             'cmd_fail_cb'       : @handle_not_mac_os};

global_var cisco_ucs_director_check = {'pre_check_fail_cb' : @cisco_ucs_director_pre_check_fail,
             'test_cmd'          : 'uname -a',
             'test_cmd_regex'    : '\tCisco UCS Director Shell Menu\n',
             'cmd_success_cb'    : @handle_cisco_ucs_director,
             'cmd_fail_cb'       : @handle_not_cisco_ucs_director};

# VMWare ESXi does not support privilege escalation - only exec checks unless shell emulation
# is required for some other reason.
global_var vmware_esxi_check = {'pre_check_fail_cb' : @vmware_esxi_pre_check_fail,
               'test_cmd'          : 'uname -a',
               'test_cmd_regex'    : "^VMkernel\s",
               'cmd_success_cb'    : @handle_vmware_esxi,
               'cmd_fail_cb'       : @handle_not_vmware_esxi};

global_var mcafee_secureos_check = {'pre_check_fail_cb' : @mcafee_secureos_pre_check_fail,
               'test_cmd'          : 'uname -a',
               'test_cmd_regex'    : "^SecureOS\s",
               'cmd_success_cb'    : @handle_mcafee_secureos,
               'cmd_fail_cb'       : @handle_not_mcafee_secureos};

global_var vmware_nsx_check = {'pre_check_fail_cb' : @vmware_nsx_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "(System type:.*NSX Manager|Name:.*vShield Edge)",
               'cmd_success_cb'    : @handle_vmware_nsx,
               'cmd_fail_cb'       : @handle_not_vmware_nsx};

global_var bigip_check = {'pre_check_fail_cb' : @bigip_pre_check_fail,
               'test_cmd'          : 'show sys version',
               'test_cmd_regex'    : "BIG-I([PQ])",
               'cmd_success_cb'    : @handle_bigip,
               'cmd_fail_cb'       : @handle_not_bigip};

global_var timos_check = {'pre_check_fail_cb' : @timos_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "^TiMOS",
               'cmd_success_cb'    : @handle_timos,
               'cmd_fail_cb'       : @handle_not_timos};

global_var ios_check = {'pre_check_fail_cb'   : @ios_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "(Cisco IOS|Cisco Internetwork Operating System Software)",
               'cmd_success_cb'    : @handle_ios,
               'cmd_fail_cb'       : @handle_not_ios};

global_var firepower_ftd_check = {'pre_check_fail_cb' : @cisco_firepower_ftd_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "Model.*\W+UUID.*\W+(?:Rules.*\W+)?(?:LSP version.*\W+)?VDB version|Model\s*:\s*Cisco\s*Firepower\s*\d+\s*Threat\s*Defense\s*\W+\d+\W+\s*Version\s*(\d.+)",
               'cmd_success_cb'    : @handle_cisco_firepower,
               'cmd_fail_cb'       : @handle_not_cisco_firepower_ftd};

global_var firepower_module_check = {'pre_check_fail_cb' : @cisco_firepower_module_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "Firepower Extensible Operating System Platform",
               'cmd_success_cb'    : @handle_cisco_firepower,
               'cmd_fail_cb'       : @handle_not_cisco_firepower_module};

global_var firepower_chassis_check = {'pre_check_fail_cb' : @cisco_firepower_chassis_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "Version:.*Startup-Vers:",
               'cmd_success_cb'    : @handle_cisco_firepower,
               'cmd_fail_cb'       : @handle_not_cisco_firepower_chassis};

global_var firepower_alt1_check = {'pre_check_fail_cb' : @cisco_firepower_alt1_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "Boot Loader version.*\WSystem version.*\WService Manager version",
               'cmd_success_cb'    : @handle_cisco_firepower_alt1,
               'cmd_fail_cb'       : @handle_not_cisco_firepower_alt1};

global_var asa_check = {'pre_check_fail_cb'   : @asa_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "(?:^|\n)Cisco Adaptive Security Appliance",
               'cmd_success_cb'    : @handle_asa,
               'cmd_fail_cb'       : @handle_not_asa};

global_var asa_cx_check = {'pre_check_fail_cb' : @asa_cx_pre_check_fail,
                'test_cmd'          : 'show version',
                'test_cmd_regex'    : "(?:^|\n)Cisco ASA CX Platform",
                'cmd_success_cb'    : @handle_asa_cx,
                'cmd_fail_cb'       : @handle_not_asa_cx};

global_var ios_xr_alt_check = {'pre_check_fail_cb'   : @ios_xr_pre_check_fail,
                'test_cmd'          : 'show version | utility head -n 20',
                'test_cmd_regex'    : "Cisco IOS XR Software",
                'cmd_success_cb'    : @handle_ios_xr,
                'cmd_fail_cb'       : @handle_not_ios_xr};

global_var ios_xr_check = {'pre_check_fail_cb'   : @ios_xr_pre_check_fail,
                'test_cmd'          : 'show version brief',
                'test_cmd_regex'    : "Cisco IOS XR Software",
                'cmd_success_cb'    : @handle_ios_xr,
                'cmd_fail_cb'       : @handle_not_ios_xr};

global_var nxos_check = {'pre_check_fail_cb' : @nxos_pre_check_fail,
             'test_cmd'          : 'show ver',
             'test_cmd_regex'    : "(?:Cisco\s)*Nexus",
             'cmd_success_cb'    : @handle_nxos,
             'cmd_fail_cb'       : @handle_not_nxos};

global_var rios_check = {'pre_check_fail_cb' : @rios_pre_check_fail,
             'test_cmd'          : 'show version',
             'test_cmd_regex'    : "Product name:[ \t]+rbt",
             'cmd_success_cb'    : @handle_rios,
             'cmd_fail_cb'       : @handle_not_rios};

global_var nxos_alt_check = {'pre_check_fail_cb' : @nxos_pre_check_fail,
                  'test_cmd'          : 'connect local-mgmt',
                  'test_cmd_regex'    : "Cisco Nexus",
                  'cmd_success_cb'    : @handle_nxos_alt,
                  'cmd_fail_cb'       : @handle_not_nxos_alt};

global_var hpux_check = {'pre_check_fail_cb' : @hpux_pre_check_fail,
              'test_cmd'          : 'uname -a',
              'test_cmd_regex'    : "(^|\s)HP-UX\s",
              'cmd_success_cb'    : @handle_hpux,
              'cmd_fail_cb'       : @handle_not_hpux_os};

global_var aix_check = {'pre_check_fail_cb' : @aix_pre_check_fail,
             'test_cmd'          : 'uname -a',
             'test_cmd_regex'    : "(^|\s)AIX\s",
             'cmd_success_cb'    : @handle_aix,
             'cmd_fail_cb'       : @handle_not_aix_os};

global_var extreme_networks_fabric_engine_check = {
              'pre_check_fail_cb' : @extreme_networks_fabric_engine_pre_check_fail,
              'test_cmd'          : 'show sys-info | no-more',
              'test_cmd_regex'    : "-Fabric\s?Engine\s",
              'cmd_success_cb'    : @handle_extreme_networks_fabric_engine,
              'cmd_fail_cb'       : @handle_not_extreme_networks_fabric_engine};

global_var exos_check = {'pre_check_fail_cb' : @exos_pre_check_fail,
              'test_cmd'          : 'show version',
              'test_cmd_regex'    : "(^|\s)ExtremeXOS\s",
              'cmd_success_cb'    : @handle_exos,
              'cmd_fail_cb'       : @handle_not_exos};

global_var freebsd_check = {'pre_check_fail_cb' : @freebsd_pre_check_fail,
                 'test_cmd'          : 'uname -a',
                 'test_cmd_regex'    : "(^|\s)FreeBSD\s",
                 'cmd_success_cb'    : @handle_freebsd,
                 'cmd_fail_cb'       : @handle_not_freebsd};

global_var zscaleros_check = {'pre_check_fail_cb' : @zscaleros_pre_check_fail,
                   'test_cmd'          : 'uname -a',
                   'test_cmd_regex'    : "(^|\s)ZscalerOS\s",
                   'cmd_success_cb'    : @handle_zscaleros,
                   'cmd_fail_cb'       : @handle_not_zscaleros};

global_var netbsd_check = {'pre_check_fail_cb' : @netbsd_pre_check_fail,
                'test_cmd'          : 'uname -a',
                'test_cmd_regex'    : "(^|\s)NetBSD\s",
                'cmd_success_cb'    : @handle_netbsd,
                'cmd_fail_cb'       : @handle_not_netbsd};

global_var solaris_check = {'pre_check_fail_cb' : @solaris_pre_check_fail,
                 'test_cmd'          : 'uname -a',
                 'test_cmd_regex'    : "SunOS",
                 'cmd_success_cb'    : @handle_solaris,
                 'cmd_fail_cb'       : @handle_not_solaris};

global_var netapp_check = {'pre_check_fail_cb' : @netapp_pre_check_fail,
                'test_cmd'          : 'version',
                'test_cmd_regex'    : "NetApp Release",
                'cmd_success_cb'    : @handle_netapp,
                'cmd_fail_cb'       : @handle_not_netapp};

global_var windows_check = {'pre_check_fail_cb' : @windows_pre_check_fail,
                 'test_cmd'          : 'cmd /C ver',
                 'test_cmd_regex'    : "(^|\s)Microsoft Windows",
                 'cmd_success_cb'    : @handle_windows,
                 'cmd_fail_cb'       : @handle_not_windows};

global_var cas_check = {'pre_check_fail_cb' : @symantec_cas_pre_check_fail,
             'test_cmd'          : 'show version',
             'test_cmd_regex'    : "^CAS release",
             'cmd_success_cb'    : @handle_symantec_cas,
             'cmd_fail_cb'       : @handle_not_symantec_cas};

global_var ucos_check = {'pre_check_fail_cb' : @cisco_ucos_pre_check_fail,
              'test_cmd'          : 'show version active',
              'test_cmd_regex'    : 'Active Version Installed Software Options:',  # Needs to match all VOSS products
              'cmd_success_cb'    : @handle_cisco_ucos,
              'cmd_fail_cb'       : @handle_not_cisco_ucos};

global_var ise_check = {'pre_check_fail_cb'   : @cisco_ise_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "Cisco Identity Services Engine",
               'cmd_success_cb'    : @handle_cisco_ise,
               'cmd_fail_cb'       : @handle_not_cisco_ise};

global_var fortios_check = {'pre_check_fail_cb' : @fortios_pre_check_fail,
               'test_cmd'            : 'get system status',
               'test_cmd_regex'      : "(Forti|Press '[Aa]' to accept)",
               'cmd_success_cb'      : @handle_fortios,
               'cmd_fail_cb'         : @handle_not_fortios};

# Version ID Support for MobileIron (RES-45750)
global_var mobileiron_check = {'pre_check_fail_cb' : @mobileiron_pre_check_fail,
                    'test_cmd'          : 'show version',
                    'test_cmd_regex'    : "(CORE|Illegal command line|s.\[Jh.\[Jo.\[Jw.\[J.\[J .\[Jv.\[Je.\[Jr.\[Js.\[Ji.\[Jo.\[Jn)",
                    'cmd_success_cb'    : @handle_mobileiron,
                    'cmd_fail_cb'       : @handle_not_mobileiron};

global_var ivanti_sentry_check = {'pre_check_fail_cb' : @ivanti_sentry_pre_check_fail,
                    'test_cmd'          : 'show version',
                    'test_cmd_regex'    : 'Sentry Standalone',
                    'cmd_success_cb'    : @handle_ivanti_sentry,
                    'cmd_fail_cb'       : @handle_not_ivanti_sentry};

global_var oracle_sbc_check = {'pre_check_fail_cb' : @oracle_sbc_pre_check_fail,
                    'test_cmd'          : 'show version',
                    'test_cmd_regex'    : "Acme\sPacket\s(?:OS\sVM\s|[0-9]+\s)SCZ([0-9]+\.[0-9]+\.[0-9]+)\sPatch\s[0-9]+\s\(Build [0-9]+\)",
                    'cmd_success_cb'    : @handle_oracle_sbc,
                    'cmd_fail_cb'       : @handle_not_oracle_sbc};

 # Version for Zyxel USG
global_var zyxel_usg_check = {'pre_check_fail_cb' : @zyxel_usg_pre_check_fail,
                    'test_cmd'          : 'show version',
                    'test_cmd_regex'    : "Zyxel Communications Corp",
                    'cmd_success_cb'    : @handle_zyxel_usg,
                    'cmd_fail_cb'       : @handle_not_zyxel_usg};

 # Firmwar Version for Zyxel 
global_var zyxel_device_check = {'pre_check_fail_cb' : @zyxel_device_pre_check_fail,
                    'test_cmd'          : 'cat /firmware/mnt/info/fwversion',
                    'test_cmd_regex'    : "^V[0-9]+\.[0-9]+\([a-zA-Z.0-9]+\)",
                    'cmd_success_cb'    : @handle_zyxel_device,
                    'cmd_fail_cb'       : @handle_not_zyxel_device};

#For Check Point users configured to drop into clish
global_var gaia_clish_check = {'pre_check_fail_cb' : @gaia_clish_pre_check_fail,
                    'test_cmd'          : 'show version all',
                    'test_cmd_regex'    : 'Product version Check Point',
                    'cmd_success_cb'    : @handle_gaia_clish,
                    'cmd_fail_cb'       : @handle_not_gaia_clish};


#For Check Point users configured to drop into expert shell
global_var gaia_expert_check = {'pre_check_fail_cb' : @gaia_expert_pre_check_fail,
                     'test_cmd'          : 'uname -a',
                     'test_cmd_regex'    : '^(Linux) +([^ ]+) +([0-9.]+-[0-9.]+cp)',
                     'cmd_success_cb'    : @handle_gaia_expert,
                     'cmd_fail_cb'       : @handle_not_gaia_expert};

#For Gaia Embedded users configured to drop into clish
global_var gaia_embedded_check = {'pre_check_fail_cb' : @gaia_embedded_pre_check_fail,
                    'test_cmd'          : 'show software-version',
                    'test_cmd_regex'    : 'This is Check Point',
                    'cmd_success_cb'    : @handle_gaia_embedded,
                    'cmd_fail_cb'       : @handle_not_gaia_embedded};

global_var cisco_viptela_check = {'pre_check_fail_cb' : @viptela_pre_check_fail,
                    'test_cmd'          : 'show system status',
                    'test_cmd_regex'    : "^Viptela \(tm\) v(edge|manage|smart) Operating System Software",
                    'cmd_success_cb'    : @handle_viptela,
                    'cmd_fail_cb'       : @handle_not_viptela};

global_var zxrosng_check = {'pre_check_fail_cb'   : @zxrosng_pre_check_fail,
               'test_cmd'          : 'show zxrp-info',
               'test_cmd_regex'    : "ZTE Router Platform Software:",
               'cmd_success_cb'    : @handle_zxrosng,
               'cmd_fail_cb'       : @handle_not_zxrosng};

global_var arista_eos_ios_check = {'pre_check_fail_cb'   : @arista_eos_ios_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "^Arista",
               'cmd_success_cb'    : @handle_arista_eos_ios,
               'cmd_fail_cb'       : @handle_not_arista_eos_ios};

global_var bluecoat_proxysg_check = {'pre_check_fail_cb'   : @bluecoat_proxysg_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "SGOS.+Proxy Edition|SGOS.+SWG Edition",
               'cmd_success_cb'    : @handle_bluecoat_proxysg,
               'cmd_fail_cb'       : @handle_not_bluecoat_proxysg};

global_var fireeye_check = {'pre_check_fail_cb'   : @fireeye_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "Product model:\s+FireEye|Version summary:\s+\w.+(?:Trellix)",
               'cmd_success_cb'    : @handle_fireeye,
               'cmd_fail_cb'       : @handle_not_fireeye};

global_var huawei_vrp_check = {'pre_check_fail_cb'   : @huawei_vrp_pre_check_fail,
               'test_cmd'          : 'display version',
               'test_cmd_regex'    : "Huawei Versatile Routing Platform Software",
               'cmd_success_cb'    : @handle_huawei_vrp,
               'cmd_fail_cb'       : @handle_not_huawei_vrp};

global_var citrix_adc_check = {'pre_check_fail_cb'   : @citrix_adc_pre_check_fail,
               'test_cmd'          : 'show ns version',
               'test_cmd_regex'    : "Net[Ss]caler",
               'cmd_success_cb'    : @handle_citrix_adc,
               'cmd_fail_cb'       : @handle_not_citrix_adc};

global_var citrix_adc_sdx_check = {'pre_check_fail_cb'   : @citrix_adc_sdx_pre_check_fail,
               'test_cmd'          : 'show systemstatus',
               'test_cmd_regex'    : "Product Name: (ADC|NetScaler) SDX",
               'cmd_success_cb'    : @handle_citrix_adc_sdx,
               'cmd_fail_cb'       : @handle_not_citrix_adc_sdx};

global_var aruba_s_check = {'pre_check_fail_cb'   : @aruba_s_pre_check_fail,
               'test_cmd'          : 'show aruba-central',
               'test_cmd_regex'    : "Aruba Central",
               'cmd_success_cb'    : @handle_aruba_s,
               'cmd_fail_cb'       : @handle_not_aruba_s};

global_var aruba_cx_check = {'pre_check_fail_cb'   : @aruba_cx_pre_check_fail,
               'test_cmd'          : 'show system',
               'test_cmd_regex'    : "\nA(?:ruba)?OS-CX Version *:",
               'cmd_success_cb'    : @handle_aruba_cx,
               'cmd_fail_cb'       : @handle_not_aruba_cx};

# This appliance does not support exec mode SSH commands
global_var aruba_cppm_check = {'pre_check_fail_cb' : @aruba_cppm_pre_check_fail,
               'test_cmd'          : 'show version',
               'test_cmd_regex'    : "\nPolicy Manager",
               'cmd_success_cb'    : @handle_aruba_cppm,
               'cmd_fail_cb'       : @handle_not_aruba_cppm};


# Attempt to ID various HP Switches, using keynames of ProCurve, 3Com, Comware
global_var hp_comware_check = {'pre_check_fail_cb'   : @hp_comware_pre_check_fail,
               'test_cmd'          : 'summary',
               'test_cmd_regex'    : "Comware Software, Version ",
               'cmd_success_cb'    : @handle_hp_comware,
               'cmd_fail_cb'       : @handle_not_hp_comware};

#The inital shell encountered when logging into ADM replies with error messages
#Here is an generic regex for a matching against the reply for a few other test_cmds
#".*ERROR: \[remove\] no value for param.*",
global_var citrix_adm_check = {'pre_check_fail_cb' : @citrix_adm_pre_check_fail,
              'test_cmd'          : "uname -a",
              'test_cmd_regex'    : "^FreeBSD citrixadm.*$",
              'cmd_success_cb'    : @handle_citrix_adm,
              'cmd_fail_cb'       : @handle_not_citrix_adm};

global_var panos_check = {'pre_check_fail_cb' : @panos_pre_check_fail,
              'test_cmd'          : 'show system info',
              'test_cmd_regex'    : "model: ((PA|pa|VM|vm|M|m)-|Panorama)",
              'cmd_success_cb'    : @handle_panos,
              'cmd_fail_cb'       : @handle_not_panos};

global_var cimc_check = {'pre_check_fail_cb' : @cisco_cimc_pre_check_fail,
              'test_cmd'          : 'show cimc',
              'test_cmd_regex'    : "\n(\d+\.\d+\([0-9.]+[A-Za-z]?\))\s+",
              'cmd_success_cb'    : @handle_cisco_cimc,
              'cmd_fail_cb'       : @handle_not_cisco_cimc};

global_var qnap_standard_check = {'pre_check_fail_cb' : @qnap_standard_pre_check_fail,
              'test_cmd'          : 'uname -a',
              'test_cmd_regex'    : "Linux\s+[^\s]+\s+[\d.]+-qnap\s",
              'cmd_success_cb'    : @handle_qnap_standard,
              'cmd_fail_cb'       : @handle_not_qnap_standard};

global_var qnap_qes_check = {'pre_check_fail_cb' : @qnap_qes_pre_check_fail,
              'test_cmd'          : 'ver -a',
              'test_cmd_regex'    : "QNAP\sModel:\s*T?ES.+\n",
              'cmd_success_cb'    : @handle_qnap_qes,
              'cmd_fail_cb'       : @handle_not_qnap_qes};

global_var acos_check = {'pre_check_fail_cb' : @acos_pre_check_fail,
                'test_cmd'          : 'show version',
                'test_cmd_regex'    : "Advanced Core OS \(ACOS\)",
                'cmd_success_cb'    : @handle_acos,
                'cmd_fail_cb'       : @handle_not_acos};

global_var adtran_check = {'pre_check_fail_cb' : @adtran_pre_check_fail,
                'test_cmd'          : 'show version',
                'test_cmd_regex'    : "ADTRAN, Inc.",
                'cmd_success_cb'    : @handle_adtran,
                'cmd_fail_cb'       : @handle_not_adtran};

global_var sophos_utm_check = {'pre_check_fail_cb' : @sophos_utm_pre_check_fail,
                'test_cmd'          : "auisys.plx --version",
                'test_cmd_regex'    : "^Astaro.*|^Sophos.*",
                'cmd_success_cb'    : @handle_sophos_utm,
                'cmd_fail_cb'       : @handle_not_sophos_utm};

global_var adeos_check = {'pre_check_fail_cb' : @cisco_adeos_pre_check_fail,
                'test_cmd'          : "show version",
                'test_cmd_regex'    : "^Cisco Application Deployment Engine OS",
                'cmd_success_cb'    : @handle_cisco_adeos,
                'cmd_fail_cb'       : @handle_not_cisco_adeos};

global_var fabricos_check = {'pre_check_fail_cb' : @fabricos_pre_check_fail,
                'test_cmd'          : 'version',
                'test_cmd_regex'    : "\nFabric OS *:",
                'cmd_success_cb'    : @handle_fabricos,
                'cmd_fail_cb'       : @handle_not_fabricos};

global_var cisco_csp_check = {'pre_check_fail_cb' : @cisco_csp_pre_check_fail,
                'test_cmd'          : "show version",
                'test_cmd_regex'    : "^Cisco Cloud Services Platform Software,",
                'cmd_success_cb'    : @handle_cisco_csp,
                'cmd_fail_cb'       : @handle_not_cisco_csp};

global_var asyncos_check = {'pre_check_fail_cb' : @cisco_asyncos_pre_check_fail,
                'test_cmd'          : "version",
                'test_cmd_regex'    : "(?:Cisco|IronPort).+(?:Web Security|Messaging Gateway|Email Security|Security (?:Virtual )?Management|Secure Web)",
                'cmd_success_cb'    : @handle_cisco_asyncos,
                'cmd_fail_cb'       : @handle_not_cisco_asyncos};

global_var cisco_ips_check = {'pre_check_fail_cb' : @cisco_ips_pre_check_fail,
                'test_cmd'          : "show version",
                'test_cmd_regex'    : "\nCisco Intrusion Prevention System,",
                'cmd_success_cb'    : @handle_cisco_ips,
                'cmd_fail_cb'       : @handle_not_cisco_ips};

global_var cisco_ip_phone_check = {'pre_check_fail_cb' : @cisco_ip_phone_pre_check_fail,
                'test_cmd'          : 'debug\ndebug\nshow version',
                'test_cmd_regex'    : "CNU[^ ]+OS\s+\d",
                'cmd_success_cb'    : @handle_cisco_ip_phone,
                'cmd_fail_cb'       : @handle_not_cisco_ip_phone};

global_var cisco_nam_check = {'pre_check_fail_cb' : @cisco_nam_pre_check_fail,
                'test_cmd'          : 'show version',
                'test_cmd_regex'    : "NAM application image version",
                'cmd_success_cb'    : @handle_cisco_nam,
                'cmd_fail_cb'       : @handle_not_cisco_nam};

global_var cisco_staros_check = {'pre_check_fail_cb' : @cisco_staros_pre_check_fail,
                'test_cmd'          : 'show version verbose',
                'test_cmd_regex'    : "Kernel Version.*-staros-.*",
                'cmd_success_cb'    : @handle_cisco_staros,
                'cmd_fail_cb'       : @handle_not_cisco_staros};

global_var ibm_storwize_check = {'pre_check_fail_cb' : @ibm_storwize_pre_check_fail,
                'test_cmd'          : 'sainfo lsservicestatus',
                'test_cmd_regex'    : "[\r\n]\s*node_code_version [0-9.]+[\r\n]",
                'cmd_success_cb'    : @handle_ibm_storwize,
                'cmd_fail_cb'       : @handle_not_ibm_storwize};

global_var dell_os10_check = {'pre_check_fail_cb' : @dell_os10_pre_check_fail,
                'test_cmd'          : 'show version',
                'test_cmd_regex'    : "((?:Force10 Networks|Dell(?: EMC)?) Real Time Operating System Software|Dell EMC Networking OS10 Enterprise)",
                'cmd_success_cb'    : @handle_dell_os10,
                'cmd_fail_cb'       : @handle_not_dell_os10};

global_var screenos_check = {'pre_check_fail_cb' : @screenos_pre_check_fail,
                'test_cmd'          : 'get system',
                'test_cmd_regex'    : "(File Name: screenos_image, Checksum: |(\n|^)Hardware Version: .+, FPGA checksum)",
                'cmd_success_cb'    : @handle_screenos,
                'cmd_fail_cb'       : @handle_not_screenos};

global_var ubiquiti_check = {'pre_check_fail_cb' : @ubiquiti_pre_check_fail,
                'test_cmd'          : 'info',
                'test_cmd_regex'    : "(^|\n)Model:\s*UAP[\r\n]+Version:\s*[0-9.]+",
                'cmd_success_cb'    : @handle_ubiquiti,
                'cmd_fail_cb'       : @handle_not_ubiquiti};

global_var iwsva_check = {'pre_check_fail_cb' : @iwsva_pre_check_fail,
                'test_cmd'          : 'show system version',
                'test_cmd_regex'    : "(^|\n)\s*IWSVA: ",
                'cmd_success_cb'    : @handle_iwsva,
                'cmd_fail_cb'       : @handle_not_iwsva};

global_var forescout_counteract_check = {'pre_check_fail_cb' : @forescout_counteract_pre_check_fail,
                'test_cmd'          : 'version',
                'test_cmd_regex'    : 'CounterACT Appliance',
                'cmd_success_cb'    : @handle_forescout_counteract,
                'cmd_fail_cb'       : @handle_not_forescout_counteract};

# There are few options that actually contain the vendor or name. Additional checks in OS include.
global_var infoblox_nios_check = {'pre_check_fail_cb' : @infoblox_nios_pre_check_fail,
                'test_cmd'          : 'show version',
                'test_cmd_regex'    : "(^|\n)\s*Version *:.*[\r\n]+SN *:.*[\r\n]+Hotfix *:",
                'cmd_success_cb'    : @handle_infoblox_nios,
                'cmd_fail_cb'       : @handle_not_infoblox_nios};

global_var dell_idrac_check = {'pre_check_fail_cb' : @dell_idrac_pre_check_fail,
                'test_cmd'          : 'racadm getversion',
                'test_cmd_regex'    : "(^|\n)\s*iDRAC Version *=",
                'cmd_success_cb'    : @handle_dell_idrac,
                'cmd_fail_cb'       : @handle_not_dell_idrac};
                
global_var arrayos_check = {'pre_check_fail_cb' : @arrayos_pre_check_fail,
'test_cmd'          : 'no pager\nshow version',
'test_cmd_regex'    : "ArrayOS",
'cmd_success_cb'    : @handle_arrayos,
'cmd_fail_cb'       : @handle_not_arrayos};

# for commands ran via an ssh shell
global_var shell_handler_checks = make_array(
  "sshlib::basic_shell_handler", make_list2(
    iwsva_check,
    firepower_ftd_check,
    firepower_module_check,
    firepower_chassis_check,
    firepower_alt1_check,
    mobileiron_check,
    zyxel_usg_check,
    citrix_adc_sdx_check,
    citrix_adc_check,                  # Citrix ADC
    zyxel_device_check,
    gaia_clish_check,
    gaia_expert_check,
    gaia_embedded_check,
    qnap_qes_check,
    sophos_utm_check,
    fabricos_check,
    cisco_csp_check,
    cisco_ips_check,
    cisco_nam_check,
    aruba_cppm_check,
    cisco_ip_phone_check,
    cisco_staros_check,
    cisco_ucs_director_check,
    ibm_storwize_check,
    mcafee_secureos_check,
    screenos_check,
    ubiquiti_check,
    infoblox_nios_check,
    dell_idrac_check,
    arrayos_check
  ),
  "sshlib::sh_shell_handler", make_list2(
    linux_check,
    mac_check,
    hpux_check,
    aix_check,
    solaris_check,
    netbsd_check,
    freebsd_check,
    openbsd_check,
    zscaleros_check,
    zyxel_device_check
  ),
  "sshlib::ios_shell_handler", make_list2(
    ios_check,
    nxos_alt_check,
    nxos_check,
    rios_check,
    asa_cx_check,                       # ASA CX needs to be checked before ASA.
    asa_check,
    ios_xr_alt_check,
    ios_xr_check,
    zxrosng_check,
    aruba_cx_check,
    bluecoat_proxysg_check,
    cimc_check,
    arista_eos_ios_check,
    fireeye_check,
    acos_check,
    adtran_check,
    dell_os10_check,
    oracle_sbc_check
  ),
  "sshlib::aruba_s_shell_handler", make_list2(aruba_s_check, hp_comware_check, ivanti_sentry_check),
  "sshlib::huawei_vrp_shell_handler", make_list2(huawei_vrp_check),
  "sshlib::netapp_shell_handler", make_list2(netapp_check),
  "sshlib::tmsh_shell_handler", make_list2(bigip_check),
  "sshlib::timos_shell_handler", make_list2(timos_check, vmware_nsx_check),
  "sshlib::exos_shell_handler", make_list2(extreme_networks_fabric_engine_check, exos_check),
  "sshlib::cisco_ucos_shell_handler", make_list2(ucos_check),
  "sshlib::cisco_adeos_shell_handler", make_list2(ise_check, adeos_check),
  "sshlib::fortios_shell_handler", make_list2(fortios_check),
  "sshlib::citrix_adm_shell_handler", make_list2(citrix_adm_check),
  "sshlib::cisco_viptela_shell_handler", make_list2(cisco_viptela_check),
  "sshlib::panos_shell_handler", make_list2(panos_check),
  "sshlib::qnap_standard_shell_handler", make_list2(qnap_standard_check),
  "sshlib::forescout_counteract_shell_handler", make_list2(forescout_counteract_check)
);

# for commands ran via ssh exec
global_var exec_checks = [
  linux_check,
  mac_check,
  hpux_check,
  aix_check,
  solaris_check,
  freebsd_check,
  netbsd_check,
  openbsd_check,
  zscaleros_check,
  vmware_esxi_check,
  cisco_ucs_director_check,           # end of uname -a checks
  fabricos_check,
  asyncos_check,                      # Cisco AsyncOS (formerly IronPort)
  exos_check,
  extreme_networks_fabric_engine_check,
  cisco_csp_check,
  cisco_ips_check,
  cisco_nam_check,
  cas_check,                          # Symantec Content Analysis (CAS)
  firepower_ftd_check,                # Although a cisco device, does not use ios_handler
  firepower_module_check,             # Although a cisco device, does not use ios_handler
  firepower_chassis_check,            # Although a cisco device, does not use ios_handler
  firepower_alt1_check,               # Although a cisco device, does not use ios_handler
  sophos_utm_check,                   # Sophos UTM
  cisco_ip_phone_check,
  cisco_staros_check,
  ibm_storwize_check,
  screenos_check,
  ubiquiti_check,
  zyxel_device_check
];

# for commands ran via rsh/rexec/telnet
global_var hostlevel_checks = [
  linux_check,
  mac_check,
  hpux_check,
  aix_check,
  solaris_check,
  freebsd_check,
  netbsd_check
];

# for commands run locally on scanner box via popen
global_var local_scanner_checks = [
  linux_check,
  mac_check,
  windows_check
];

global_var release, use_hostlevel, failure_kb_msg, failure_kb_type;

global_var cmd_interrupted_names_local_checks = "";
port_g = NULL;
sock_g = NULL;
info_t = 0;
