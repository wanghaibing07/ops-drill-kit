"""Strict validation of identity observations for an L02 transient unit.

This verifies parsed observations only. systemd parsing, process start time,
configuration file security and live socket ownership remain backend duties.
"""
import re
from l02_policy import require


def validate_unit(run_id, props, argv, config_path):
    require(isinstance(run_id,str) and re.fullmatch(r'[0-9a-f]{24}',run_id), 'invalid run')
    name='opsdrill-l02-'+run_id+'.service'
    prefix='/etc/nginx/opsdrill-l02-isolated/'+run_id+'/'
    expected=prefix+'nginx.conf'
    require(config_path==expected, 'invalid config path')
    require(props.get('Id')==name and props.get('LoadState')=='loaded' and
            props.get('FragmentPath')=='/run/systemd/transient/'+name and
            props.get('Type')=='exec' and props.get('User','') in ('','root') and
            props.get('DropInPaths','')=='', 'foreign or unsafe service')
    require(argv==['/usr/sbin/nginx','-p',prefix,'-c','nginx.conf','-g','daemon off;'], 'unexpected nginx command')
    require(props.get('ControlGroup')=='/system.slice/'+name, 'invalid control group')
    invocation=props.get('InvocationID','')
    require(re.fullmatch(r'[0-9a-f]{32}',invocation) is not None, 'invalid invocation')
    return invocation
