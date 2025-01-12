import os
from flask import Flask, request, render_template, redirect, url_for
import pandas as pd
from tabulate import tabulate
import re

# Initialize Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

analysis_output = []

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
            analysis_output.append(f'[{str(i+1)}]:: No Policy found for connection as: {list(set(ipsec_connections))[0]}')

        if 'no policy configured' in line and 'ignoring request to establish IPsec SA' not in line:
            _no_policy_configured(i,comes_line_phase_1)
            policy_error = True
            comes_line_phase_1 = None
        
        if "gw validation failed" in line:
            print('BINGO')
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
            start_index_failure = comes_line_phase_1.index("comes")
            failure_message = comes_line_phase_1[start_index_failure:]
            for prev_line in lines[:i]:
                if "EAP identity request" in prev_line:
                    analysis_output.append(f'[{str(i+1)}]::VPN with IP Connection as:: '+failure_message+' is down due to bad PSK in EAP Request from clinet')

        if "negotiation timeout, deleting" in line:
            timeout_index = i
        
        if timeout_index != -1 and abs(i - timeout_index) <= 5:
            print('hit the old con exp')
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
                    analysis_output.append(f'[{str(i+1)}]:: Gateway in passive mode for connection: '+match.group(1))
                    break
        
        # Check for rekey of phaase-2
        if "rekey" in line:
            # Extract the connection information using string manipulation
            parts = line.split()
            for part in parts:
                if "->" in part and ":" in part:
                    analysis_output.append(f'[{str(i+1)}]:: Rekey connection found: {part}')
                    break
        # Rekey failures catch
        if 'rekey in progress' in line:
            retransmit_count = 0
            for j in range(i + 1, min(i + 150, len(lines))):
                if 'RETRANSMIT_CREATE_CHILD' in lines[j]:
                    retransmit_count += 1
                if retransmit_count >= 3:
                    analysis_output.append(f'[{str(i+1)}]:: rekey in progress followed by 3 RETRANSMIT_CREATE_CHILD. Possible re-key failures')

        
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
                analysis_output.append(f'[{str(i+1)}]:: 5 consecutive keep-alives detected for connection: {part}. Check: \n-> ISP issues \n->re-key issues \n-> Check if peer is Meraki')

        # Check for network unreachable
        if "Network is unreachable" in line:
            # Use regex to extract the IP connection details
            match = re.search(r"(\d+\.\d+\.\d+\.\d+:\d+->\d+\.\d+\.\d+\.\d+:\d+)", line)
            if match:
                analysis_output.append(f'[{str(i+1)}]:: Network Unreachable for connection: {match.group(1)} Check: \n->Next hop IP \n->Route to the peer \n->Arp of next hop')

        if 'ike' in line and 'send EAP message to FNBAM' in line:
            context = lines[i:i + 15]
            user, group, eap_id = None, None, None
            for entry in context:
                if 'EAP user' in entry:
                    user = entry.split('"')[1]  # Extract "vpnuser"
                if 'auth group' in entry:
                    group = entry.split()[-1]  # Extract "local-users"
                if 'EAP' in entry and 'pending' in entry:
                    match = re.search(r"EAP (\d+)", entry)
                    if match:
                        eap_id = match.group(1)
            if user and group==None  and eap_id==None:
                analysis_output.append(f'   The auth log anlysis for the above connection \n    user: {user} group: Unknown   Fnbamd-ID: Unknown')
            if user and group  and eap_id:
                analysis_output.append(f'   The auth log anlysis for the above connection \n    user: {user} group: {group}   Fnbamd-ID: {eap_id}')
            if user and eap_id:
                analysis_output.append(f'   The auth log anlysis for the above connection \n    user: {user} group: Unknown   Fnbamd-ID: {eap_id}')
            if group  and eap_id:
                analysis_output.append(f'   The auth log anlysis for the above connection \n    user: Unknown group: {group}   Fnbamd-ID: {eap_id}')                            
            print(user)
            if eap_id:
                rest_lines = lines[i:]
                for k,remaining_line in enumerate(rest_lines):
                    
                    if eap_id in remaining_line:
                        analysis_output.append(f'   [{str(i+k+1)}]{remaining_line.strip()}')
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
                                analysis_output.append(f'<span style="color: red;">[{str(i+k+1)}] Trying Local authentication with local-user and the current status is {result}</span>')
                            else:
                                if code == '1':
                                    result = 'denied'
                                if code == '0':
                                    result = 'success'
                                if code == '2':
                                    result = 'Challenged or still in progress or need more info'
                                analysis_output.append(f'<span style="color: red;">[{str(i+k+1)}] Trying radius authentication and the current status as {result}</span>')

                        else:
                            analysis_output.append(f'<span style="color: red;">[{str(i+k+1)}] Check the server response in the above line</span>')
                    if eap_id in remaining_line and 'result' in remaining_line:
                        context = rest_lines[k:k + 7]
                        for info in context:
                            if 'EAP' in info and 'result' not in info:
                                analysis_output.append(f'       [{str(i+k+1)}]{info.strip()}')


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
    analysis_output.append(f'[{str(i+1)}]::'+sa_proposal+' VPN with IP Connection as:'+failure_message+' is UP for phase-1')

# Phase-2 check helper function
def _phase_2_check(i,line,lines,comes_line_phase_1,selectors):
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    analysis_output.append(f'[{str(i+1)}]::'+'VPN with IP Connection as -> '+failure_message+' is UP for phase-2 \n'+selectors)

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
                analysis_output.append(f'[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Phase-2 connection '+failure_message.split()[1]+' due to PFS being disabled in remote peer')
            if "IKEv2" in ike_phase_1_type:
                Ike_type = "IKE-V2"
                analysis_output.append(f'[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Phase-2 connection '+failure_message.split()[1]+' due to PFS being disabled in remote peer')
            # turn on phase_2 flag
            phase_2=True
            
        # check pfs disable on local peer 
        if ("PFS is disabled" in Ike_param[1] and "PFS is disabled" not in Ike_param[0]):
            if "IKEv1" in ike_phase_1_type:
                Ike_type = "IKE-V1"
                analysis_output.append(f'[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Phase-2 connection '+failure_message.split()[1]+' due to PFS being disabled in local peer')
            if "IKEv2" in ike_phase_1_type:
                Ike_type = "IKE-V2"
                analysis_output.append(f'[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Phase-2 connection '+failure_message.split()[1]+' due to PFS being disabled in local peer')
            # turn on phase_2 flag
            phase_2=True
    
    # only hit this statement if phase_2 remains false
    if "IKEv1" in ike_phase_1_type and phase_2==False:
        Ike_type = "IKE-V1"
        analysis_output.append(f'[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' With mismatch as'+NETWORK_ID+'\n'+str(parse_to_table(mismatch_param)))

    # only hit this statement if phase_2 remains false
    if "IKEv2" in ike_phase_1_type and phase_2==False:
        Ike_type = "IKE-V2"
        analysis_output.append(f'[{str(i+1)}]::'+' Negotiation Failure for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' With mismatch as'+NETWORK_ID+'\n'+str(parse_to_table(mismatch_param)))


def _phase_1_psk_fail(i,line,comes_line_phase_1,ike_phase_1_type):
    Ike_type = ''
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    if "IKEv1" in ike_phase_1_type:
        Ike_type = "IKE-V1"
        analysis_output.append(f'[{str(i+1)}]::'+' PSK Mismatch for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' Please check PSK ')
    if "IKEv2" in ike_phase_1_type:
        Ike_type = "IKE-V2"
        analysis_output.append(f'[{str(i+1)}]::'+' PSK Mismatch for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' Please check PSK ')

def _notify_no_proposal_chosen(i,line,comes_line_phase_1):
    analysis_output.append(f'[{str(i+1)}]::'+' Peer connection: '+comes_line_phase_1+ ' is notifying a no proposal chosen or negotiation mismatch')

def _gw_validation_fail(i,line,comes_line_phase_1,ike_phase_1_type):
    Ike_type = ''
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    if "IKEv1" in ike_phase_1_type:
        Ike_type = "IKE-V1"
        analysis_output.append(f'[{str(i+1)}]::'+' Gateway validation fail for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' Please Check: \n->peer ID \n->certificate settings \n->network ID')
    if "IKEv2" in ike_phase_1_type:
        Ike_type = "IKE-V2"
        analysis_output.append(f'[{str(i+1)}]::'' Gateway validation fail for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' Please Check: \n->peer ID \n->certificate settings \n->network ID')

def _peer_id_fail(i,line,comes_line_phase_1,ike_phase_1_type):
    Ike_type = ''
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    if "IKEv1" in ike_phase_1_type:
        Ike_type = "IKE-V1"
        analysis_output.append(f'[{str(i+1)}]::'+' PEER ID fail for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' Please Check: ->peer ID')
    if "IKEv2" in ike_phase_1_type:
        Ike_type = "IKE-V2"
        analysis_output.append(f'[{str(i+1)}]::'+' PEER ID fail for '+f'{Ike_type}'+ ' Connection '+failure_message.split()[1]+' Please Check: ->peer ID')


def _phase_2_subset(i,line,lines,selectors):
    accepted_proposals = ''
    if i + 1 < len(lines):
        analysis_output.append(f'[{str(i+1)}]:: phase-2 matched by intersection. Accepted proposals are: \n' + selectors + '\n advised to use matching selectors and not sub/super sets')

# phase_2 selector mismatch on responder
def _phase_2_ts_mismatch_responder(i,line,lines,comes_line_phase_1,ike_phase_1_type,selectors):
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    if i + 1 < len(lines):
        if "IKEv1" in ike_phase_1_type:
            Ike_type = "IKE-V1"
            analysis_output.append(f'[{str(i+1)}]:: phase2 selector mismatch for incoming traffic selectors \n' + selectors + '\n advised to check traffic selectors on initiatior for \n' + f'{Ike_type}' + ' connection ' + f'{failure_message}')
        if "IKEv2" in ike_phase_1_type:
            Ike_type = "IKE-V2"
            analysis_output.append(f'[{str(i+1)}]:: phase2 selector mismatch for incoming traffic selectors \n' + selectors + '\n advised to check traffic selectors on initiatior for \n' + f'{Ike_type}' + ' connection ' + f'{failure_message}')

# phase_2 selector mismatch on initiator
def _phase_2_ts_mismatch_initiator(i,line,lines,comes_line_phase_1,ike_phase_1_type):
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    if "IKEv1" in ike_phase_1_type:
        Ike_type = "IKE-V1"
        analysis_output.append(f'[{str(i+1)}]:: phase2 selector mismatch \n advised to check traffic selectors on responder for \n' + f'{Ike_type}' + ' connection ' + f'{failure_message}')
    if "IKEv2" in ike_phase_1_type:
        Ike_type = "IKE-V2"
        analysis_output.append(f'[{str(i+1)}]:: phase2 selector mismatch \n advised to check traffic selectors on responder for \n' + f'{Ike_type}' + ' connection ' + f'{failure_message}')

def _no_policy_configured(i,comes_line_phase_1):
    start_index_failure = comes_line_phase_1.index("comes")
    failure_message = comes_line_phase_1[start_index_failure:]
    analysis_output.append(f'[{str(i+1)}]:: No Policy is Configured for connection'+failure_message)

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
                            analysis_output.append(f'[{str(k+1)}]::VPN with IP Connection as:: '+connection_match.group(1)+' is down due to negotiation or timeout')
                        else:
                            analysis_output.append(f'[{str(i+1)}]:: VPN with IP Connection as: '+connection_match.group(1)+' is down for Phase-1 due to retransmission failures \n  Possible issues could be: \n -> NAT-T blocked \n -> ISP blocking IKE \n -> port forward misconfig\n -> Network Overlay ID mismatch')
                if retransmit_match:
                    retransmit_type = retransmit_match.group(1)
                    retransmit_info = retransmit_match.group(2)
                    if 'response' in retransmit_type or 'RESPONSE' in retransmit_type:
                        analysis_output.append(f'[{str(k+1)}]::Reason for VPN with IP Connection as: '+retransmit_info+' could be for the follwing reasons for error: '+retransmit_type +' \nCheck \n->NAT-4500 blocked \n->authentication failures on the peer ' )
                    else:
                        analysis_output.append(f'[{str(k+1)}]::Reason for VPN with IP Connection as: '+retransmit_info+' for retransmission is for: '+retransmit_type )

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
        
        if logfile.filename == '':
            return "No file selected", 400
        
        # Save the uploaded file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], logfile.filename)
        logfile.save(filepath)

        # Read and process the file
        ike_log = read_file(filepath)
        if ike_log is None:
            return "Error reading file", 500

        # Clear previous analysis output
        global analysis_output
        analysis_output = []
        ike_parser(ike_log)
        def deduplicate_array(arr):
            unique_elements = []
            for item in arr:
                if item not in unique_elements:
                    unique_elements.append(item)
            return unique_elements

        # Render the analysis output
        return render_template("result.html", results=deduplicate_array(analysis_output))
    
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True,host="0.0.0.0", port=8888)
