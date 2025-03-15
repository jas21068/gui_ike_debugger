import os
from flask import Flask, request, render_template, redirect, url_for
import pandas as pd
from tabulate import tabulate
import re
import requests
import json
from data_model import Model
from difflib import get_close_matches

# Initialize Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

analysis_output = []
Incoming_conn = []
SAML = False

def read_file(filepath):
    """Reads the content of the file."""
    try:
        with open(filepath, 'r') as file:
            content = file.read()
            return str(content)
    except FileNotFoundError:
        return None
    except Exception as e:
        return str(e)

# (Keep your existing ike_parser and other functions here)
# '========================================================================================================================================'
# '========================================================================================================================================'
# '========================================================================================================================================'
# '========================================================================================================================================'
# '========================================================================================================================================'

def ike_parser(text):
    """
    Finds and prints lines containing the phrase 'SA proposal chosen' in the given text.

    :param text: The multi-line string to search through.
    """
    comes_line_phase_1 = None
    ike_phase_1_type = None
    comes_line = None
    NETWORK_ID=''
    fail_line = None
    lines = text.splitlines()
    connection_info_retrans = None
    timeout_index = -1
    src_pattern = r"src .*?:([\d.]+-[\d.]+)"
    dst_pattern = r"dst .*?:([\d.]+-[\d.]+)"
    src_pattern_mis = r"TSi_0\s\d+:[\d.]+-[\d.]+:\d+"
    dst_pattern_mis = r"TSr_0\s\d+:[\d.]+-[\d.]+:\d+"
    src_selectors = None
    dst_selectors = None
    policy_error = False
    src=''
    dst=''
    src_mis=''
    dst_mis=''
    RED = '\033[91m'
    RESET = '\033[0m'
    passive_mode_pattern = r"ignoring request to establish IPsec SA, gateway is in passive mode"
    connection_pattern = r"IPsec SA connect \d+ (\d+\.\d+\.\d+\.\d+->\d+\.\d+\.\d+\.\d+:\d+)"
    for i, line in enumerate(lines):

        # Phase-1 check
        if "SA proposal chosen" in line and "no SA proposal chosen" not in line:
            _phase_1_check(i,line,lines,comes_line_phase_1)
            comes_line_phase_1 = None
        
        # Phase-2 selector object storage
        if re.search(src_pattern, line):
            src = re.search(src_pattern, line).group(1)
        if re.search(src_pattern_mis, line):
            src_mis = re.search(src_pattern_mis, line).group(0)
         
        # Phase-2 selector object storage    
        if re.search(dst_pattern, line):
            dst = re.search(dst_pattern, line).group(1)
        if re.search(dst_pattern_mis, line):
            dst_mis = re.search(dst_pattern_mis, line).group(0)

        if 'processing notify type NO_PROPOSAL_CHOSEN' in line:
            _notify_no_proposal_chosen(i,line,comes_line_phase_1)
            comes_line_phase_1 = None 

        # phase-2 check    
        if "added IPsec SA" in line:
            selectors = ''
            if src and dst:
                selectors = f'[{str(i+1)}]:: The selectors are: \n'+'src: '+src+'\n'+'dst: '+dst             
            _phase_2_check(i,line,lines,comes_line_phase_1,selectors)    
            comes_line_phase_1 = None    
            src_selectors = None
            dst_selectors = None
        
        #Flagging for no policy configured

        if 'no policy configured' in line and 'ignoring request to establish IPsec SA' in line:
            ipsec_lines = lines[-10:]
            ipsec_sa_pattern = re.compile(r"IPsec SA connect .* (\d+\.\d+\.\d+\.\d+->\d+\.\d+\.\d+\.\d+:\d+)")
            ipsec_connections = [match.group(1) for line in ipsec_lines if (match := ipsec_sa_pattern.search(line))]
            analysis_output.append(f'<span style="color: red;">[{str(i+1)}]:: No matching Firewall policy found for the IKE negotiation: {list(set(ipsec_connections))[0]} </span>')

        if 'no policy configured' in line and 'ignoring request to establish IPsec SA' not in line:
            _no_policy_configured(i,comes_line_phase_1)
            policy_error = True
            comes_line_phase_1 = None
        
        if "gw validation failed" in line:
            # print('BINGO')
            last_10_lines = []
            start_index = max(i - 10, 0) 
            last_10_lines.append(line)
            for j in range(start_index, i):
                last_10_lines.append(lines[j])

            # Check if "FQDN 'admin'" is in any of the last 10 lines
            if any("received peer identifier" in log for log in last_10_lines):
                _peer_id_fail(i,line,comes_line_phase_1,ike_phase_1_type)
                comes_line_phase_1 = None
                ike_phase_1_type = None
                comes_line = None
                fail_line = None
            else:
                if comes_line_phase_1:
                    _gw_validation_fail(i,line,comes_line_phase_1,ike_phase_1_type)
                    comes_line_phase_1 = None
                    ike_phase_1_type = None
                    comes_line = None
                    fail_line = None

        if "VPN_NETWORK_ID" in line:
            # Check up to 5 lines below the matched line
            for j in range(i + 1, min(i + 6, len(lines))):
                if "NETWORK ID :" in lines[j]:
                    # Extract the number after "NETWORK ID :"
                    parts = lines[j].split(":")
                    if len(parts) > 1:
                        try:
                            NETWORK_ID=' Network ID mismatch with value '+parts[-1]
                        except ValueError:
                            pass  # Ignore lines that don't have a valid number

        #Check for Phase-1 Negotiation failures
        if "negotiation failure" in line or "no proposal chosen" in line:
            fail_line=i
            if comes_line_phase_1 and policy_error == False:
                Ike_param = _extract_lines(lines, comes_line, fail_line)
                _phase_1_2_mismatch(i,line,comes_line_phase_1,ike_phase_1_type,Ike_param,NETWORK_ID)
                comes_line_phase_1 = None
                ike_phase_1_type = None
                comes_line = None
                fail_line = None
                NETWORK_ID=''
            else:
                policy_error = False

        
        if "PSK auth failed: probable pre-shared key mismatch" in line:
            if comes_line_phase_1:
                _phase_1_psk_fail(i,line,comes_line_phase_1,ike_phase_1_type)
                comes_line_phase_1 = None
                ike_phase_1_type = None
                comes_line = None
                fail_line = None
        
        # Grabs the connection details for the phase-1 mismatch
        if "comes" in line:
            match = re.search(r'comes ([\d.]+):\d+', line)
            if match:
                Incoming_conn.append(match.group(1))
            comes_line_phase_1 = line
            comes_line = i + 3
            if i + 1 < len(lines):
                ike_phase_1_type = lines[i + 1]

            # _phase_1_mismatch_V1(i,line,lines)
        
        if "matched by intersection" in line:
            selectors = ''
            if src and dst:
                selectors = f'[{str(i+1)}]:: The selectors are: \n'+'src: '+src+'\n'+'dst: '+dst 
            _phase_2_subset(i,line,lines,selectors)

        if "failed to match peer selectors" in line:
            fail_line=i
            selectors = ''
            if comes_line_phase_1:
                if src_mis and dst_mis:
                    selectors = f'[{str(i+1)}]:: The selectors are: \n'+'src: '+src_mis+'\n'+'dst: '+dst_mis 
                _phase_2_ts_mismatch_responder(i,line,lines,comes_line_phase_1,ike_phase_1_type,selectors)
                comes_line_phase_1 = None
                ike_phase_1_type = None
                comes_line = None
                fail_line = None
                src_selectors = None
                dst_selectors = None
        
        if 'TS_UNACCEPTABLE' in line:
            fail_line=i
            if comes_line_phase_1:
                _phase_2_ts_mismatch_initiator(i,line,lines,comes_line_phase_1,ike_phase_1_type)
                comes_line_phase_1 = None
                ike_phase_1_type = None
                comes_line = None
                fail_line = None

        if "connection expiring due to phase1 down" in line and timeout_index == -1:
            _phase_1_retrans_check_1(line,lines,i)
        if "connection expiring due to phase1 down" in line and timeout_index != -1:
            if comes_line_phase_1:
                start_index_failure = comes_line_phase_1.index("comes")
                failure_message = comes_line_phase_1[start_index_failure:]
                proceed = True
                for prev_line in reversed(lines[:i]):
                    if 'rad_conn_timeout-Connction' in prev_line:
                        proceed = False
                        analysis_output.append(f'<span style="color: orange;">[{str(i+1)}]::VPN with IP for the IKE negotiation:: '+failure_message+' is down, most likely due to the Radius server timing out </span>')
                    elif "EAP identity request" in prev_line and proceed==True:
                        analysis_output.append(f'<span style="color: orange;">[{str(i+1)}]::VPN with IP for the IKE negotiation:: '+failure_message+' is down, most likely due to a Preshared key mismatch between the Fortigate and the client </span>')

        if "negotiation timeout, deleting" in line:
            timeout_index = i
        
        if timeout_index != -1 and abs(i - timeout_index) <= 5:
            # print('hit the old con exp')
            if "connection expiring due to phase1 down" in line:
                # Search for the connection info pattern in the log
                _phase_1_retrans_check_1(line,lines,i)
                timeout_index = -1
        
        #No Policy found use case
        if re.search(passive_mode_pattern, line):
            # Look ahead to find connection details in the next lines
            for j in range(i + 1, len(lines)):
                match = re.search(connection_pattern, lines[j])
                if match:
                    analysis_output.append(f'<span style="color: red;">[{str(i+1)}]:: The VPN tunnel is configured to be in passive-mode: </span>'+match.group(1))
                    break
        
        # Check for rekey of phaase-2
        if "rekey" in line:
            # Extract the connection information using string manipulation
            parts = line.split()
            for part in parts:
                if "->" in part and ":" in part:
                    analysis_output.append(f'<span style="color: yellow;">[{str(i+1)}]:: Rekey connection found: {part}</span>')
                    break
        # Rekey failures catch
        if 'rekey in progress' in line:
            retransmit_count = 0
            for j in range(i + 1, min(i + 150, len(lines))):
                if 'RETRANSMIT_CREATE_CHILD' in lines[j]:
                    retransmit_count += 1
                if retransmit_count >= 3:
                    analysis_output.append(f'<span style="color: red;">[{str(i+1)}]:: A rekey is observed to be in progress, and, multiple RETRANSMIT_CREATE_CHILD messages observed. Possible re-key failure. </span>')

        
        # Check for keepalives
        if 'keepalive' in line:
            # Extract the IP address from the line
            parts = line.split()
            for part in parts:
                if '->' in part:
                    connection_ip = part.split('->')[1].split(':')[0]
                    break
            else:
                continue

            # Count 'keepalive' occurrences in the next 25 lines
            keepalive_count = sum(1 for l in lines[i:i + 25] if 'keepalive' in l)

            # Check if it meets the condition
            if keepalive_count >= 5:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}]:: 5 consecutive keep-alives transmitted for the IKE negotiation: {part}. Check:</span> \n-> ISP issues \n->re-key issues \n-> Check if peer is Meraki')

        # Check for network unreachable
        if "Network is unreachable" in line:
            # Use regex to extract the IP connection details
            match = re.search(r"(\d+\.\d+\.\d+\.\d+:\d+->\d+\.\d+\.\d+\.\d+:\d+)", line)
            if match:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}]:: Network Unreachable error observed for the IKE negotiation: {match.group(1)} Check:</span> \n->Next hop IP \n->Route to the peer \n->Arp of next hop')

#IKE v1 auth logic
        if 'ike' in line and 'sending XAUTH request' in line:
            context = lines[i:i + 150]
            user, group, eap_id = None, None, None
            for entry in context:
                if 'XAUTH user' in entry:
                    user = entry.split('"')[1]  # Extract "vpnuser"
                if 'auth group' in entry:
                    group = entry.split()[-1]  # Extract "local-users"
                if 'XAUTH' in entry and 'pending' in entry and 'ike' in entry:
                    match = re.search(r"XAUTH (\d+)", entry)
                    if match:
                        eap_id = match.group(1)
            if user and group==None  and eap_id==None:
                analysis_output.append(f'<span style="color: yellow;">   The auth log anlaysis for the above connection </span>\n    user: {user} group: Unknown   Fnbamd-ID: Unknown')
            if user and group  and eap_id:
                analysis_output.append(f'<span style="color: yellow;">   The auth log anlasis for the above connection </span>\n    user: {user} group: {group}   Fnbamd-ID: {eap_id}')
            if user and eap_id:
                analysis_output.append(f'<span style="color: yellow;">   The auth log anlaysis for the above connection </span>\n    user: {user} group: Unknown   Fnbamd-ID: {eap_id}')
            if group  and eap_id:
                analysis_output.append(f'<span style="color: yellow;">   The auth log anlaysis for the above connection </span>\n    user: Unknown group: {group}   Fnbamd-ID: {eap_id}')                            
            if eap_id:
                rest_lines = lines[i:]
                for k,remaining_line in enumerate(rest_lines):
                    
                    if eap_id in remaining_line:
                        analysis_output.append(f'   [{str(i+k+1)}]{remaining_line.strip()}')
                    if eap_id in remaining_line and "FNBAM_DENIED" in remaining_line:
                        if SAML == False:
                            analysis_output.append(f'<span style="color: red;">[{str(i+k+1)}] Fnbamd DENIED DETECTED</span>')
                        if SAML == True:
                            analysis_output.append(f'<span style="color: red;">[{str(i+k+1)}] Fnbamd DENIED DETECTED with SAML.</span> <span style="color: yellow;">\n->Check Group Mismatch \n-> Check Group Attribute/Name Mismatch</span>')
                        last_10_lines = rest_lines[max(0, k - 9):k + 1]
                        if any("find_matched_usr_grps-Failed group matching" in l for l in last_10_lines):
                            analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] Fnbamd failure observed due to a possible group mismatch</span>')
                    if 'fnbam_user_auth_group_match' in remaining_line and eap_id in remaining_line:
                            analysis_output.append(f'<span style="color: yellow;">[{str(i+k+1)}] Check the server response in the above line</span>')
                    if 'fnbamd_comm_send_result' in remaining_line and eap_id in remaining_line:
                        match = re.search(r"Sending result (\d+)", remaining_line)
                        if match:
                            result_value = int(match.group(1))
                            if result_value == 0:
                                analysis_output.append(f'<span style="color: green;">[{str(i+k+1)}] fnbamd success for the above connection </span>')
                            if result_value == 1:
                                analysis_output.append(f'<span style="color: red;">[{str(i+k+1)}] fnbamd deny for the above connection </span>')
                            if result_value == 2:
                                analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] fnbamd Challenge for the above connection </span>')
                            if result_value == 5:
                                analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] fnbamd ERROR for the above connection </span>')
                        else:
                            analysis_output.append(f'<span style="color: yellow;">[{str(i+k+1)}] Check the Fnbam result in the above line \n 0-->SUCCESS 1---> DENY 2--> CHALLENGE</span>')
                    if eap_id in remaining_line and 'result' in remaining_line:
                        context = rest_lines[k:k + 7]
                        for info in context:
                            if 'XAUTH' in info and 'result' not in info:
                                analysis_output.append(f'       [{str(i+k+1)}]{info.strip()}')
                    if eap_id in remaining_line and 'FNBAM_DENIED' in remaining_line:
                        for prev_line in reversed(rest_lines[:k]):
                            if "ldap_next_state" in prev_line and 'ldap_next_state-State' not in prev_line:
                                analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] LDAP failure observed. Possible reason: {prev_line}</span>')
                            if "fnbamd_ldap_parse_response-Error" in prev_line:
                                analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] LDAP failure observed. Possible reason: {prev_line}</span>')
                    if eap_id in remaining_line and 'FNBAM_ERROR' in remaining_line:
                        analysis_output.append(f'<span style="color: yellow;">[{str(i+k+1)}] FNBAMD ERROR means possible FNBAMD Unavailaibility due to lack of servers or non_reachability or DNS issues</span>')
                        for prev_line in reversed(rest_lines[:k]):
                            if "__ldap_try_next_server-No more server to try." in prev_line:
                                analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] LDAP log found for FNBAM_error. Possible reason: {prev_line}</span>')
                            if "fnbamd_dns_parse_resp" in prev_line and 'wrong dns format' in prev_line:
                                analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] LDAP log found for deny. DNS issue for LDAP server detected</span>')
                    if eap_id in remaining_line and 'FNBAM_TIMEOUT' in remaining_line:
                        analysis_output.append(f'<span style="color: yellow;">[{str(i+k+1)}] FNBAM_TIMEOUT means possible FNBAMD Unavailaibility due to lack of servers or non_reachability or retries exceeded for wrong credentials</span>')
                        for prev_line in reversed(rest_lines[:k]):
                            if "__ldap_try_next_server-No more server to try." in prev_line:
                                analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] LDAP log found for FNBAM_error. Possible reason: {prev_line}</span>')
                            if "fnbamd_cfg_ldap_update_reachability" in prev_line and 'conn_fails' in prev_line:
                                analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] LDAP log found for deny. Server not reachable. Possible reason: {prev_line}</span>')
                    # RADIUS LOGIC 
                    if eap_id in remaining_line and 'fnbamd_rad_process-Result' in remaining_line:
                        proceed = True
                        match1 = re.search(r"svr\s'([^']+)'", remaining_line)
                        if match1:
                            svr = match1.group(1)  # Extracts 'EAP_PROXY'
                            for prev_line in reversed(rest_lines[:k]):
                                if "fnbamd_cfg_radius_update_reachability" in prev_line and 'conn_fails' in prev_line and svr in prev_line:
                                    analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] RADIUS log found for deny. Server not reachable. Possible reason: {prev_line}</span>')
                                if "__rad_try_next_server-No more server to try." in prev_line:
                                    analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] RADIUS log found for FNBAM_error. Possible reason: {prev_line}</span>')
                                if "__fnbamd_rad_dns_cb-Resolved" in prev_line and '0.0.0.0' in prev_line and svr in prev_line:
                                    analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] RADIUS reason for  deny. DNS issue for RADIUS server detected</span>') 
                                    proceed = False
                        pattern = r"Result from radius svr '.*?' is (\d+)"
                        match = re.search(pattern, remaining_line)
                        if match and proceed == True:
                            if int(match.group(1)) == 10:
                                analysis_output.append(f'<span style="color: red;">[{str(i+k+1)}] Possible credential(likely:username) mismatch for Radius server, for username: {user} </span>')
                            if int(match.group(1)) == 1:
                                analysis_output.append(f'<span style="color: red;">[{str(i+k+1)}] Possible credential(likely:password) mismatch for Radius server, for username: {user} </span>')


#IKE v2 auth logic
        if 'ike' in line and 'send EAP message to FNBAM' in line:
            context = lines[i:i + 150]
            user, group, eap_id = None, None, None
            for entry in context:
                if 'EAP user' in entry:
                    user = entry.split('"')[1]  # Extract "vpnuser"
                if 'auth group' in entry:
                    group = entry.split()[-1]  # Extract "local-users"
                if 'EAP' in entry and 'pending' in entry and 'ike' in entry:
                    match = re.search(r"EAP (\d+)", entry)
                    if match:
                        eap_id = match.group(1)
            if user and group==None  and eap_id==None:
                analysis_output.append(f'<span style="color: yellow;">   The auth log anlaysis for the above connection \n    user: {user} group: Unknown   Fnbamd-ID: Unknown</span>')
            if user and group  and eap_id:
                analysis_output.append(f'<span style="color: yellow;">   The auth log anlaysis for the above connection \n    user: {user} group: {group}   Fnbamd-ID: {eap_id}</span>')
            if user and eap_id and group==None:
                analysis_output.append(f'<span style="color: yellow;">   The auth log anlaysis for the above connection \n    user: {user} group: Unknown   Fnbamd-ID: {eap_id}</span>')
            if group  and eap_id and user==None:
                analysis_output.append(f'<span style="color: yellow;">   The auth log anlaysis for the above connection \n    user: Unknown group: {group}   Fnbamd-ID: {eap_id}</span>')                            
            if eap_id:
                rest_lines = lines[i:]
                for k,remaining_line in enumerate(rest_lines):
                    
                    if eap_id in remaining_line:
                        analysis_output.append(f'   [{str(i+k+1)}]{remaining_line.strip()}')
                    if eap_id in remaining_line and "FNBAM_DENIED" in remaining_line:
                        if SAML == False:
                            analysis_output.append(f'<span style="color: red;">[{str(i+k+1)}] Fnbamd DENIED DETECTED</span>')
                        if SAML == True:
                            analysis_output.append(f'<span style="color: red;">[{str(i+k+1)}] Fnbamd DENIED DETECTED with SAML.</span> <span style="color: yellow;">\n->Check Group Mismatch \n-> Check Group Attribute/Name Mismatch</span>')
                        last_10_lines = rest_lines[max(0, k - 9):k + 1]
                        if any("find_matched_usr_grps-Failed group matching" in l for l in last_10_lines):
                            analysis_output.append(f'<span style="color: red;">[{str(i+k+1)}] Fnbamd failing due to a possible user group mismatch</span>')
                    if "handle_req-Error starting session" in remaining_line and SAML == True:
                        analysis_output.append(f'<span style="color: yellow;">[{str(i+k+1)}] Fnbamd failing to start. \n->Check if SAML server is responsive \n-> Check: https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-IPsec-SAML-Authentication-fails-due-to/ta-p/339738</span>')
                    if 'fnbamd_comm_send_result' in remaining_line and eap_id in remaining_line:
                        match = re.search(r"Sending result (\d+)", remaining_line)
                        if match:
                            result_value = int(match.group(1))
                            if result_value == 0:
                                analysis_output.append(f'<span style="color: green;">[{str(i+k+1)}] fnbamd success for the above connection </span>')
                            if result_value == 1:
                                analysis_output.append(f'<span style="color: red;">[{str(i+k+1)}] fnbamd deny for the above connection </span>')
                            if result_value == 2:
                                analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] fnbamd Challenge for the above connection </span>')
                            if result_value == 5:
                                analysis_output.append(f'<span style="color: orange;">[{str(i+k+1)}] fnbamd ERROR for the above connection </span>')
                        else:
                            analysis_output.append(f'<span style="color: yellow;">[{str(i+k+1)}] Check the Fnbam result in the above line \n 0-->SUCCESS 1---> DENY 2--> CHALLENGE</span>')                    
                    if 'fnbamd_rad_process-Result' in remaining_line:
                        pattern = r"svr\s'([^']+)'\s.*?is\s(\d+)"
                        match = re.search(pattern, remaining_line)
                        if match:
                            svr = match.group(1)  # Extracts 'EAP_PROXY'
                            code = match.group(2)  # Extracts '1'
                            if svr == 'EAP_PROXY':
                                result = ''
                                if code == '1':
                                    result = 'denied'
                                if code == '0':
                                    result = 'success'
                                if code == '2':
                                    result = 'Challenged or still in progress or need more info'
                                analysis_output.append(f'<span style="color: yellow;">[{str(i+k+1)}] Trying Local authentication with local-user and the current status is {result}</span>')
                            else:
                                if code == '1':
                                    result = 'denied'
                                if code == '0':
                                    result = 'success'
                                if code == '2':
                                    result = 'Challenged or still in progress or need more info'
                                analysis_output.append(f'<span style="color: yellow;">[{str(i+k+1)}] Trying radius authentication and the current status as {result}</span>')

                        else:
                            analysis_output.append(f'<span style="color: yellow;">[{str(i+k+1)}] Check the server response in the above line</span>')
                    if eap_id in remaining_line and 'result' in remaining_line:
                        context = rest_lines[k:k + 7]
                        for info in context:
                            if 'EAP' in info and 'result' not in info:
                                analysis_output.append(f'[{str(i+k+1)}]{info.strip()}')

# Adding known issue
        if 'compute DH shared secret request queued' in line:
            pattern = "compute DH shared secret request queued"
            count = 1

            # Check the next 20 lines for additional matches
            for j in range(1, 21):
                if i + j < len(lines) and re.search(pattern, lines[i + j]):
                    count += 1
            if count >= 10:
                analysis_output.append(f'<span style="color: red;">Known Issue detected for fnbamd crash \n Please check if there are fnbamd crashes in the crashlog. \n Refer: https://community.fortinet.com/t5/FortiClient/Troubleshooting-Tip-Dial-up-IPsec-VPN-in-aggressive-mode-when/ta-p/189924</span>')

# CERT AUTH LOGIC
        if 'ike' in line and 'received peer identifier' in line:
            match = re.search(r"received peer identifier (.+)", line)
            if match:
                peer_identifier = match.group(1)
                analysis_output.append(f'[{str(i+1)}]<span style="color: yellow;">Cert auth detected as : {peer_identifier}</span>')
            else:
                analysis_output.append(f'<span style="color: yellow;">Cert auth detected at line [{str(i+1)}]</span>')
            
        if 'ike' in line and 'peer cert' in line:
            match = re.search(r"subject='([^']+)', issuer='([^']+)'", line)
            if match:
                subject = match.group(1)
                issuer = match.group(2)
                analysis_output.append(f'<span style="color: yellow;">Peer cert as :</span> \nSubject: {subject} \nIssuer: {issuer}')
        if 'ike' in line and 'peer CA cert' in line:
            match = re.search(r"subject='([^']+)', issuer='([^']+)'", line)
            if match:
                subject = match.group(1)
                issuer = match.group(2)
                print(f"Subject: {subject}")
                print(f"Issuer: {issuer}")
                analysis_output.append(f'<span style="color: yellow;">Peer CA cert :</span> \nSubject: {subject} \nIssuer: {issuer}')
        if 'ike' in line and 'signature verification succeeded' in line:
            analysis_output.append(f'<span style="color: green;">[{str(i+1)}]Cert auth succeeded')
        if 'ike' in line and 'certificate validation failed' in line:
            analysis_output.append(f'<span style="color: red;">[{str(i+1)}]IKE negotiation failure observed, due to a possible certificate authentication failure.')
            analysis_output.append(f'<span style="color: yellow;">Please Check:\n CA signed bt valid CA or the root CA istalled in FGT \n Bad PKI user \n Re-check cert auth settings: {issuer} ')

# tunnel flap 1
        if 'ike' in line and 'ISAKMP SA DELETE-NOTIFY' in line:
            pattern = r"(\d+\.\d+\.\d+\.\d+:\d+->\d+\.\d+\.\d+\.\d+:\d+)"
            match = re.search(pattern, line)

            if match:
                extracted_value = match.group(1)
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] Tunnel going down for connection {extracted_value}.</span>')
            else:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] Tunnel going down for connection {line}.</span>')

# tunnel flap 2
        if 'ike' in line and 'deleting IPsec SA with SPI' in line:
            analysis_output.append(f'<span style="color: red;">[{str(i+1)}] Tunnel going down for VPN with SPI as:  {line}.</span>')

# tunnel flap 3
        if 'ike' in line and 'del route' in line:
            del_route_pattern = re.compile(r"del route (\d+\.\d+\.\d+\.\d+/\d+\.\d+\.\d+\.\d+)")
            moving_route_pattern = re.compile(r"moving route (\d+\.\d+\.\d+\.\d+/\d+\.\d+\.\d+\.\d+)")
            del_match = del_route_pattern.search(line)
            if del_match:
                subnet = del_match.group(1)
                analysis_output.append(f'<span style="color: yellow;">[{str(i+1)}] deleting a route with IKE add-route detected for route: {subnet}.</span>')
                search_range = range(max(0, i - 5), min(len(lines), i + 6))
                for j in search_range:
                    if i != j and "moving route" in lines[j]:
                        move_match = moving_route_pattern.search(lines[j])
                        if move_match and move_match.group(1) == subnet:
                            analysis_output.append(f'<span style="color: red;">[{str(i+1)}] Possible flapping: Matching del and moving route found for subnet: {subnet}.</span>')

# twin connection detected

        if 'ike' in line and 'twin connection detected' in line:
            analysis_output.append(f'<span style="color: red;">[{str(i+1)}] twin IPSEC connection detected. </span>')




def _extract_lines(lines, start_line, end_line):
    input_string = "\n".join(lines[start_line-1:end_line])
    split_keyword = "my proposal"
    split_index = input_string.find(split_keyword)
    
    # Split the string into two parts
    if split_index != -1:
        part1 = input_string[:split_index].strip()
        part2 = input_string[split_index:].strip()
        return [part1, part2]
    else:
        return None, None



# Phase-1 check helper function
def _phase_1_check(i,line,lines,comes_line_phase_1):
    start_index = line.index("SA proposal chosen")
    sa_proposal = line[start_index:]
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    # Also get the connection for which SA proposal is chosen
    analysis_output.append(f'<span style="color: green;">[{str(i+1)}]::'+sa_proposal+' VPN with IP for the IKE negotiation:'+failure_message+' is UP for phase-1</span>')

# Phase-2 check helper function
def _phase_2_check(i,line,lines,comes_line_phase_1,selectors):
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    analysis_output.append(f'<span style="color: green;">[{str(i+1)}]::'+'VPN with IP for the IKE negotiation -> '+failure_message+' is UP for phase-2</span> \n'+selectors)

# Phase-1/2 mismatch helper function
def _phase_1_2_mismatch(i,line,comes_line_phase_1,ike_phase_1_type,Ike_param,NETWORK_ID):
    Ike_type = ''
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    mismatch_param = ''    
    phase_2=False
    def compare_ike_proposals(string1, string2):
        param = []
        # Regular expression to extract the relevant IKE parameters
        pattern = r"type=([A-Z_]+),\s*val=([A-Za-z0-9_]+)(?:,\s*key-len=(\d+))?"

        # Extract the parameters from both strings
        def extract_parameters(s):
            # Clean up extra whitespace and capture parameters
            return re.findall(pattern, s.replace("\n", " ").replace("\r", " ").strip())

        params1 = extract_parameters(string1)
        params2 = extract_parameters(string2)

        mismatched_params = []

        # Compare parameters
        for p1, p2 in zip(params1, params2):
            if p1 != p2:
                mismatched_params.append((p1, p2))

        if mismatched_params:
            for p1, p2 in mismatched_params:
                # print(f"Parameter 1: {p1} | Parameter 2: {p2}")
                param.append(f"Incoming: {p1} | local: {p2}")
        return " ,, ".join(param)
    
    # Statement to check for phase-1 mismatch and also for phase-2 diff
    if Ike_param[0] is not None and Ike_param[1] is not None:
        mismatch_param = compare_ike_proposals(Ike_param[0], Ike_param[1])
        
        # check pfs disable on remote peer 
        if ("PFS is disabled" in Ike_param[0] and "PFS is disabled" not in Ike_param[1]):
            if "IKEv1" in ike_phase_1_type:
                Ike_type = "IKE-V1"
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'+' Negotiation Failure observed for '+f'{Ike_type}'+ ' Phase-2 connection '+failure_message.split()[1]+' due to PFS being disabled in remote peer</span>')
            if "IKEv2" in ike_phase_1_type:
                Ike_type = "IKE-V2"
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'+' Negotiation Failure observed for '+f'{Ike_type}'+ ' Phase-2 connection '+failure_message.split()[1]+' due to PFS being disabled in remote peer</span>')
            # turn on phase_2 flag
            phase_2=True
            
        # check pfs disable on local peer 
        if ("PFS is disabled" in Ike_param[1] and "PFS is disabled" not in Ike_param[0]):
            if "IKEv1" in ike_phase_1_type:
                Ike_type = "IKE-V1"
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'+' Negotiation Failure observed for '+f'{Ike_type}'+ ' Phase-2 connection '+failure_message.split()[1]+' due to PFS being disabled in local peer</span>')
            if "IKEv2" in ike_phase_1_type:
                Ike_type = "IKE-V2"
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'+' Negotiation Failure observed for '+f'{Ike_type}'+ ' Phase-2 connection '+failure_message.split()[1]+' due to PFS being disabled in local peer</span>')
            # turn on phase_2 flag
            phase_2=True
    
    # only hit this statement if phase_2 remains false
    if "IKEv1" in ike_phase_1_type and phase_2==False:
        Ike_type = "IKE-V1"
        analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' With mismatch as</span>'+NETWORK_ID+'\n'+str(parse_to_table(mismatch_param)))

    # only hit this statement if phase_2 remains false
    if "IKEv2" in ike_phase_1_type and phase_2==False:
        Ike_type = "IKE-V2"
        analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'+' Failure for '+f'{Ike_type}'+ ' negotiation '+failure_message.split()[1]+' With mismatch as</span>'+NETWORK_ID+'\n'+str(parse_to_table(mismatch_param)))


def _phase_1_psk_fail(i,line,comes_line_phase_1,ike_phase_1_type):
    Ike_type = ''
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    if "IKEv1" in ike_phase_1_type:
        Ike_type = "IKE-V1"
        analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'+' Preshared key (PSK) mismatch for '+f'{Ike_type}'+ ' negotiation '+failure_message.split()[1]+' Please check PSK </span>')
    if "IKEv2" in ike_phase_1_type:
        Ike_type = "IKE-V2"
        analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'+' Preshared key (PSK) mismatch for '+f'{Ike_type}'+ ' negotiation '+failure_message.split()[1]+' Please check PSK</span> ')

def _notify_no_proposal_chosen(i,line,comes_line_phase_1):
    analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'+' IKE negotiation: '+comes_line_phase_1+ '</span>')
    analysis_output.append(f'<span style="color: red;">[{str(i+1)}]no proposal chosen or negotiation mismatch </span>')
    analysis_output.append(f'<span style="color: red;">[{str(i+1)}]{line.strip()}</span>')

def _gw_validation_fail(i,line,comes_line_phase_1,ike_phase_1_type):
    Ike_type = ''
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    if "IKEv1" in ike_phase_1_type:
        Ike_type = "IKE-V1"
        analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'+' Gateway validation fail for '+f'{Ike_type}'+ ' negotiation '+failure_message.split()[1]+' Please Check:</span> \n->peer ID \n->certificate settings \n->network ID')
    if "IKEv2" in ike_phase_1_type:
        Ike_type = "IKE-V2"
        analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'' Gateway validation fail for '+f'{Ike_type}'+ ' negotiation '+failure_message.split()[1]+' Please Check: </span>\n->peer ID \n->certificate settings \n->network ID')

def _peer_id_fail(i,line,comes_line_phase_1,ike_phase_1_type):
    Ike_type = ''
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    if "IKEv1" in ike_phase_1_type:
        Ike_type = "IKE-V1"
        analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'+' PEER ID fail for '+f'{Ike_type}'+ ' negotiation '+failure_message.split()[1]+' Please Check: ->peer ID</span>')
    if "IKEv2" in ike_phase_1_type:
        Ike_type = "IKE-V2"
        analysis_output.append(f'<span style="color: red;">[{str(i+1)}]::'+' PEER ID fail for '+f'{Ike_type}'+ ' negotiation '+failure_message.split()[1]+' Please Check: ->peer ID</span>')


def _phase_2_subset(i,line,lines,selectors):
    accepted_proposals = ''
    if i + 1 < len(lines):
        analysis_output.append(f'<span style="color: yellow;">[{str(i+1)}]:: phase-2 matched by intersection. Accepted proposals are: \n' + selectors + '\n advised to use matching selectors and not sub/super sets</span>')

# phase_2 selector mismatch on responder
def _phase_2_ts_mismatch_responder(i,line,lines,comes_line_phase_1,ike_phase_1_type,selectors):
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    if i + 1 < len(lines):
        if "IKEv1" in ike_phase_1_type:
            Ike_type = "IKE-V1"
            analysis_output.append(f'<span style="color: red;">[{str(i+1)}]:: phase2 selector mismatch for incoming traffic selectors</span> \n' + selectors + '\n advised to check traffic selectors on initiatior for \n' + f'{Ike_type}' + ' negotiation ' + f'{failure_message}')
        if "IKEv2" in ike_phase_1_type:
            Ike_type = "IKE-V2"
            analysis_output.append(f'<span style="color: red;">[{str(i+1)}]:: phase2 selector mismatch for incoming traffic selectors</span> \n' + selectors + '\n advised to check traffic selectors on initiatior for \n' + f'{Ike_type}' + ' negotiation ' + f'{failure_message}')

# phase_2 selector mismatch on initiator
def _phase_2_ts_mismatch_initiator(i,line,lines,comes_line_phase_1,ike_phase_1_type):
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    if "IKEv1" in ike_phase_1_type:
        Ike_type = "IKE-V1"
        analysis_output.append(f'<span style="color: red;">[{str(i+1)}]:: phase2 selector mismatch \n advised to check traffic selectors on responder for \n' + f'{Ike_type}' + ' negotiation ' + f'{failure_message}</span>')
    if "IKEv2" in ike_phase_1_type:
        Ike_type = "IKE-V2"
        analysis_output.append(f'<span style="color: red;">[{str(i+1)}]:: phase2 selector mismatch \n advised to check traffic selectors on responder for \n' + f'{Ike_type}' + ' negotiation ' + f'{failure_message}</span>')

def _no_policy_configured(i,comes_line_phase_1):
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    analysis_output.append(f'<span style="color: red;">[{str(i+1)}]:: No Firewall policy is Configured for connection</span>'+failure_message)

# check for retrans for phase-1 down
def _phase_1_retrans_check_1(line,lines,i):
    timeout_pattern = r"negotiation timeout, deleting"
    phase1_down_pattern = r"connection expiring due to phase1 down"
    connection_info_pattern = r"(\d+\.\d+\.\d+\.\d+:\d+->\d+\.\d+\.\d+\.\d+:\d+)"
    retransmit_pattern = r"(\w+)\):\s*(\d+\.\d+\.\d+\.\d+:\d+->\d+\.\d+\.\d+\.\d+:\d+)"

    for j in range(max(0, i - 15), min(len(lines), i + 15)):
        if re.search(phase1_down_pattern, lines[j]):
            # Search for connection info in the vicinity
            for k in range(max(0, i - 15), min(len(lines), i + 15)):
                connection_match = re.search(connection_info_pattern, lines[k])
                retransmit_match = re.search(retransmit_pattern, lines[k])
                if connection_match:
                    if retransmit_match:
                        retransmit_type = retransmit_match.group(1)
                        if 'response' in retransmit_type or 'RESPONSE' in retransmit_type:
                            analysis_output.append(f'<span style="color: red;">[{str(k+1)}]::VPN for the IKE negotiation: '+connection_match.group(1)+' is down due to negotiation timeout</span>')
                        else:
                            analysis_output.append(f'<span style="color: red;">[{str(i+1)}]:: VPN for the IKE negotiation: '+connection_match.group(1)+' is down for Phase-1 due to retransmission failures</span> \n  Possible issues could be: \n -> NAT-T blocked \n -> ISP blocking IKE \n -> port forward misconfig\n -> Network Overlay ID mismatch \n -> Possible PSK mismatch')
                if retransmit_match:
                    retransmit_type = retransmit_match.group(1)
                    retransmit_info = retransmit_match.group(2)
                    if 'response' in retransmit_type or 'RESPONSE' in retransmit_type:
                        analysis_output.append(f'<span style="color: orange;">[{str(k+1)}]::Failure reason for IKE negotiation: '+retransmit_info+' could be for the follwing reasons for error: </span>'+retransmit_type +' \nCheck \n->NAT-4500 blocked \n->authentication failures on the peer ' )
                    else:
                        analysis_output.append(f'<span style="color: orange;">[{str(k+1)}]::Failure reason for IKE negotiation: '+retransmit_info+' for retransmission is for: </span>'+retransmit_type )

def parse_to_table(data_string):
    # Split the string into individual comparisons
    entries = data_string.split(",, ")

    # Initialize lists to store parsed data
    incoming_data = []
    local_data = []

    # Parse each entry and extract incoming and local information
    for entry in entries:
        try:
            incoming_part, local_part = entry.split(" | ")

            # Extract the key and value parts for incoming and local
            incoming_key, incoming_val1, incoming_val2 = eval(incoming_part.split(": ")[1])
            local_key, local_val1, local_val2 = eval(local_part.split(": ")[1])

            # Append the parsed values to the respective lists
            incoming_data.append([incoming_key, incoming_val1, incoming_val2])
            local_data.append([local_key, local_val1, local_val2])
        except:
            return 'Please check if any VPN tunnels are configured for the above connection details'

    # Create DataFrames for Incoming and Local data
    incoming_df = pd.DataFrame(incoming_data, columns=["Key", "Value1", "Value2"])
    local_df = pd.DataFrame(local_data, columns=["Key", "Value1", "Value2"])

    # Combine Incoming and Local data into a single table
    combined_df = pd.concat(
        [incoming_df.add_prefix("Incoming_"), local_df.add_prefix("Local_")], axis=1
    )

    # Pretty-print the table
    return tabulate(combined_df, headers="keys", tablefmt="grid")

def saml_parser(text):
    magic_number=''
    analysis_output.append(f'======================================================== \n<span style="color: Yellow;">SAML AUTHENTICATION DETECTED</span>\n======================================================== ')
    if re.search(r'authd_http_wait_saml_msg', text):
        analysis_output.append(f'<span style="color: green;">AUTHD DEBUGS DETECTED.SAML SESSION CO-RELATION will work</span>')
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if 'authd_http_wait_saml_msg' in line:
                found_ips = [ip for ip in Incoming_conn if re.search(r'\b' + re.escape(ip) + r'\b', line)]
                if found_ips:
                    analysis_output.append(f'<span style="color: yellow;">[{str(i+1)}] AUTHD SESSION FOUND for ike connection</span> \n {line}')
                    for j in range(i + 1, min(i + 11, len(lines))):
                        if "authd_saml_login_req" in lines[j]:
                            print(j)
                            match = re.search(r"magic=([a-f0-9]+)", lines[j])
                            if match:
                                magic_number = match.group(1)
                                analysis_output.append(f'<span style="color: green;">MAGIC ID for SAML session found as: {magic_number}</span>')
            if magic_number in line and 'samld_send_common_reply' in line:
                for j in range(i, min(i + 50, len(lines))):
                    if 'samld_send_common_reply' in lines[j] and 'magic' in lines[j]:
                        analysis_output.append(f'<span style="color:  green;">[{str(i+1)}] MAGIC ID AS:{line}</span>')
                    if 'samld_send_common_reply' in lines[j] and 'identity/claims' in lines[j]:
                        match = re.search(r'/identity/claims/(.*)', lines[j])
                        if match:
                            analysis_output.append(f'   <span style="color: yellow;"> [{str(i+1)}] {match.group(1)}</span>')
                    if 'samld_send_common_reply' in lines[j] and 'group' in lines[j]:
                        match = re.search(r"group'\s*'([\w-]+)'", lines[j])
                        if match:
                            analysis_output.append(f'   <span style="color: yellow;">[{str(i+1)}] GROUP: {match.group(1)}</span>')
                    if 'samld_send_common_reply' in lines[j] and "'name'" in lines[j]:
                        email = re.search(r"'name'\s+'([^']+)'", lines[j])
                        if email:
                            analysis_output.append(f'   <span style="color: yellow;">[{str(i+1)}] NAME: {email.group(1)}</span>')

            if 'samld_sp_login_resp' in line and 'Failed to verify signature' in line:
                analysis_output.append(f'<span style=": red;">[{str(i+1)}] Wrong SAML certficate on FortiGate Detected. Please check certificate on Fortigate for SAML</span>')
            if 'samld_send_common_reply' in line and 'Failed to verify signature' in line:
                analysis_output.append(f'<span style=": red;">[{str(i+1)}] Wrong SAML certficate on FortiGate Detected. Please check certificate on Fortigate for SAML</span>')
            if ('samld_send_common_reply' in line or '__samld_sp_login_resp' in line) and 'Generic error when an IdP or an SP ' in line:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] Invalid request, ACS Url in request <ACS link> does not match configured ACS Url. Please refer to: </span> \n https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-Companion-for-troubleshooting-SSL-VPN-with/ta-p/217719')
            if ('samld_send_common_reply' in line or '__samld_sp_login_resp' in line) and 'The identifier of a provider is unknown to #LassoServer' in line:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] The identifier of a provider is unknown to #LassoServer. Please check if there is a typo Please refer to: </span> \n https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-Companion-for-troubleshooting-SSL-VPN-with/ta-p/217719')
            if 'fsv_saml_login_response' in line and 'No group info in SAML response' in line:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] No group in SAML reponse Detected. Please check the IDP for group attached to the user Please check if there is a typo Please refer to: </span> \n https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-Companion-for-troubleshooting-SSL-VPN-with/ta-p/217719')
            if 'fsv_saml_login_response' in line and 'No user name info in SAML response' in line:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] No user in SAML reponse Detected. Please check the IDP for user availaibility .Please refer to: </span> \n https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-Companion-for-troubleshooting-SSL-VPN-with/ta-p/217719')
            if '__samld_sp_login_resp' in line and 'Clock skew issue' in line:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] Clock Skey Issue Detected. To fix the issue, make sure that time is in sync on both the SP and IdP sides. .Please refer to: </span> \n https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-Companion-for-troubleshooting-SSL-VPN-with/ta-p/217719')

    else:
        analysis_output.append(f'<span style="color: yellow;">AUTHD DEBUGS NOT DETECTED. SAML SESSION CO-RELATION may not be 100% correct</span>')
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if 'samld_send_common_reply' in line and 'magic' in line:
                analysis_output.append(f'<span style="color:  green;">[{str(i+1)}] MAGIC ID AS:{line}</span>')
            if 'samld_send_common_reply' in line and 'identity/claims' in line:
                match = re.search(r'/identity/claims/(.*)', line)
                if match:
                    analysis_output.append(f'   <span style="color: yellow;"> [{str(i+1)}] {match.group(1)}</span>')
            if 'samld_send_common_reply' in line and 'group' in line:
                match = re.search(r"group'\s*'([\w-]+)'", line)
                if match:
                    analysis_output.append(f'   <span style="color: yellow;">[{str(i+1)}] GROUP: {match.group(1)}</span>')
            if 'samld_send_common_reply' in line and "'name'" in line:
                email = re.search(r"'name'\s+'([^']+)'", line)
                if email:
                    analysis_output.append(f'   <span style="color: yellow;">[{str(i+1)}] NAME: {email.group(1)}</span>')
            if 'samld_sp_login_resp' in line and 'Failed to verify signature' in line:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] Wrong SAML certficate on FortiGate Detected. Please check certificate on Fortigate for SAML</span>')
            if 'samld_send_common_reply' in line and 'Failed to verify signature' in line:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] Wrong SAML certficate on FortiGate Detected. Please check certificate on Fortigate for SAML</span>')
            if ('samld_send_common_reply' in line or '__samld_sp_login_resp' in line) and 'Generic error when an IdP or an SP ' in line:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] Invalid request, ACS Url in request <ACS link> does not match configured ACS Url. Please refer to: </span> \n https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-Companion-for-troubleshooting-SSL-VPN-with/ta-p/217719')
            if ('samld_send_common_reply' in line or '__samld_sp_login_resp' in line) and 'The identifier of a provider is unknown to #LassoServer' in line:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] The identifier of a provider is unknown to #LassoServer. Please check if there is a typo Please refer to: </span> \n https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-Companion-for-troubleshooting-SSL-VPN-with/ta-p/217719')
            if 'fsv_saml_login_response' in line and 'No group info in SAML response' in line:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] No group in SAML reponse Detected. Please check the IDP for group attached to the user Please check if there is a typo Please refer to: </span> \n https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-Companion-for-troubleshooting-SSL-VPN-with/ta-p/217719')
            if 'fsv_saml_login_response' in line and 'No user name info in SAML response' in line:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] No user in SAML reponse Detected. Please check the IDP for user availaibility .Please refer to: </span> \n https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-Companion-for-troubleshooting-SSL-VPN-with/ta-p/217719')
            if '__samld_sp_login_resp' in line and 'Clock skew issue' in line:
                analysis_output.append(f'<span style="color: red;">[{str(i+1)}] Clock Skey Issue Detected. To fix the issue, make sure that time is in sync on both the SP and IdP sides. .Please refer to: </span> \n https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-Companion-for-troubleshooting-SSL-VPN-with/ta-p/217719')

# ENDS the business logic
# '========================================================================================================================================'
# '========================================================================================================================================'
# '========================================================================================================================================'
# '========================================================================================================================================'
# '========================================================================================================================================'


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Check if a file is uploaded
        if 'logfile' not in request.files:
            return "No file uploaded", 400
        
        logfile = request.files['logfile']
        debug_logs = request.form.get('debuglogs', 'false')

        if logfile.filename == '':
            return "No file selected", 400
        
        #log_dir = '/Users/Vito/gui_project/gui_ike_debugger/uploads'
        log_dir = os.path.join(os.getcwd(), "uploads")
        def remove_files_in_folder(folder_path):
            # Loop through all files in the directory and remove them
            for filename in os.listdir(folder_path):
                file_path = os.path.join(folder_path, filename)
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    print(f"Removed: {file_path}")
        remove_files_in_folder(log_dir)
        # Save the uploaded file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], logfile.filename)
        logfile.save(filepath)

        # Read and process the file
        ike_log = read_file(filepath)
        if ike_log is None:
            return "Error reading file", 500

        # Clear previous analysis output
        global analysis_output
        global Incoming_conn
        global SAML
        analysis_output = []
        Incoming_conn = []
        SAML = False

        if re.search(r'samld', ike_log):
            SAML = True
        ike_parser(ike_log)
        if SAML == True:
            saml_parser(ike_log)
        def deduplicate_array(arr):
            unique_elements = []
            for item in arr:
                if item not in unique_elements:
                    unique_elements.append(item)
            return unique_elements

        # Render the analysis output
        return render_template("result.html", results=deduplicate_array(analysis_output))
    
    return render_template("index.html")

@app.route("/run_script", methods=["GET"])
def run_script():


    # Reprocess the original log file
    log_files = os.listdir(app.config['UPLOAD_FOLDER'])
    if not log_files:
        return "No log file found", 500
    
    latest_log = os.path.join(app.config['UPLOAD_FOLDER'], log_files[-1])  # Get the last uploaded file

    ike_log = read_file(latest_log)
    if ike_log is None:
        return "Error reading file", 500

    # Clear previous analysis output
    global analysis_output
    global Incoming_conn
    global SAML
    analysis_output = []
    Incoming_conn = []
    SAML = False

    if re.search(r'samld', ike_log):
        SAML = True
    ike_parser(ike_log)
    if SAML == True:
        saml_parser(ike_log)

    unique_elements = []
    for item in analysis_output:
        if item not in unique_elements:
            unique_elements.append(item)
    solutions = []
    pattern = r'<span style="color: (red|orange);">(.*?)</span>'

    # Loop through each element and extract the solution text
    for text in unique_elements:
        matches = re.findall(pattern, text)
        for match in matches:
            solution_text = f"What is the solution for: {match[1]}"
            solutions.append(solution_text)
    question = "\n".join(solutions)
    def find_best_match(errors, knowledge_base):
        results = []
        
        # Iterate over the errors in the first list
        for error in errors:
            # Extract the error message by removing the initial part (e.g., "What is the solution for: ")
            error_message = error.split("for: ")[-1].strip()

            # Find the best match in the knowledge base
            best_match = get_close_matches(error_message, [item['question'] for item in knowledge_base], n=1, cutoff=0.5)

            if best_match:
                match_question = best_match[0]
                # Find the matched dictionary
                matched_entry = next(item for item in knowledge_base if item['question'] == best_match[0])
                # Append the match in the desired format
                results.append({
                    match_question: {
                        "context": matched_entry['context'],
                        "answer": matched_entry['answer']
                    }
                })
        
        return results
    matched_results = find_best_match(solutions, Model.data_model)
    if matched_results == []:
        url = "http://localhost:11434/api/generate"
        data = {
            "model": "llama3:latest",
            "prompt": f"Answer in less than 250 words in respect to Fortigate error as shown below for an IPSEC Connection: \n {question}"
        }
        response = requests.post(url, json=data)
        print(response)
        result = response.text
        lines = result.split("\n")
        responses = []
        for line in lines:
            try:
                data = json.loads(line)
                responses.append(data["response"])
            except json.JSONDecodeError:
                pass  # Skip any invalid JSON lines

        # Combine the responses into a full sentence
        final_sentence = "".join(responses)
        
        return final_sentence  # Return output as HTML

    else:
        unique_data = []
        seen = set()
        for item in matched_results:
            item_str = json.dumps(item, sort_keys=True)  # Convert dictionary to a string for hashing
            if item_str not in seen:
                seen.add(item_str)
                unique_data.append(item)
        data_as_string = json.dumps(unique_data, indent=4)
        print(f"Answer in less than 150 words in points with respect to Fortigate error as shown below for an IPSEC Connection: \n {question} \n Find the soution in the below List with each elemnt as a dictionary with key as an error mntioned above with the value as the context and answer \n {data_as_string} \n if the errors do not exist in the list then skip the response solution for that error")
        url = "http://localhost:11434/api/generate"
        data = {
            "model": "llama3:latest",
            "prompt": f"Answer in points in a readable format with respect to Fortigate error as shown below for an IPSEC Connection: \n {question} \n Find the soution only in the below List with each element as a dictionary with key as an error mntioned above with the value as the context and answer \n \n{data_as_string} \n \nif the errors do not exist in the list then skip the response solution for that error. Make it in points in a good format for human reading and use only the information provided."
        }
        response = requests.post(url, json=data)
        print(response)
        result = response.text
        lines = result.split("\n")
        responses = []
        for line in lines:
            try:
                data = json.loads(line)
                responses.append(data["response"])
            except json.JSONDecodeError:
                pass  # Skip any invalid JSON lines

        # Combine the responses into a full sentence
        final_sentence = "".join(responses)
        return final_sentence  # Return output as HTML

@app.route("/about")
def about():
    return render_template("about.html")

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True,host="0.0.0.0", port=8888)
