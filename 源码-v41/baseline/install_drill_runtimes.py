#!/usr/bin/env python3
"""Install pinned drill runtimes from a root-controlled staged source tree.

Dry-run by default. Existing destinations and incomplete state are retained.
This is a clean-install candidate, not an in-place runtime upgrader.
"""
import argparse,fcntl,hashlib,json,os,re,secrets,stat,subprocess,sys,tempfile
from pathlib import Path
TASKS=[{'name': 'l02-legacy', 'installer': 'scripts/install_l02.py', 'args': ['drills/linux/L02'], 'target': 'l02'}, {'name': 'l02-v2', 'installer': 'scripts/install_l02_v2.py', 'args': ['drills/linux/L02/recovery-v2'], 'target': 'l02-recovery-v2'}, {'name': 'l04', 'installer': 'scripts/install_l04.py', 'args': ['drills/linux/L04'], 'target': 'l04'}, {'name': 'm01', 'installer': 'scripts/install_m01.py', 'args': ['drills/mysql/M01'], 'target': 'm01'}, {'name': 'm02', 'installer': 'scripts/install_m02.py', 'args': ['drills/mysql/M02'], 'target': 'm02'}, {'name': 'm03', 'installer': 'scripts/install_m03_mysql.py', 'args': ['experimental/m03/mysql-v1'], 'target': 'm03-mysql-v1'}, {'name': 'n03', 'installer': 'scripts/install_n03_c01.py', 'args': ['experimental/n03-c01'], 'target': 'n03'}, {'name': 'n04-legacy', 'installer': 'drills/network/N04/install_n04.py', 'args': ['drills/network/N04'], 'target': 'n04'}, {'name': 'n04-v2', 'installer': 'drills/network/N04/recovery-v2/install_n04_v2.py', 'args': ['drills/network/N04/recovery-v2'], 'target': 'n04-recovery-v2'}, {'name': 'n01', 'installer': 'scripts/install_n01.py', 'args': ['drills/network/N01/n01.py', 'drills/network/N01/n01_watchdog.py'], 'target': 'n01'}, {'name': 'n02', 'installer': 'scripts/install_n02.py', 'args': ['drills/network/N02/n02.py'], 'target': 'n02'}, {'name': 'c01-v2', 'installer': 'scripts/install_c01_v2.py', 'args': ['experimental/n03-c01/c01_control_v2.py'], 'target': 'c01-v2'}]
PINS={'drills/linux/L02/l02_audit.py': 'fbed2c8254298d2a1a949ba67445729934edf3ab81851d9b6f7c88878094683f', 'drills/linux/L02/l02_cli.py': '5f98e65c4ebd988bf8d4cec3206fc9b6cd8ea8362c788119f7bf9002970e8d2d', 'drills/linux/L02/l02_config_lifecycle.py': 'a0cd65197f4411340eba0a133096e477212f880e08729e9ad372c1faa905c4bc', 'drills/linux/L02/l02_initialize.py': '70487c50033c5cfb0145b8392110915c19470b40ceeb932caae6573d40dc29a2', 'drills/linux/L02/l02_isolated.py': '9261ead42dfff96672ed1beab6efff7e6330db3dcc7340f65138f7a2e4ce1a8f', 'drills/linux/L02/l02_journal_avc.py': '9b1433956277e122134d536adab232b92f7589f6b4d27715c850518c923f1d8e', 'drills/linux/L02/l02_linux_config.py': 'e20aa533d9151ca868c2c14ecc46f3914888f2a1cee7c5969bde95d9c6e66078', 'drills/linux/L02/l02_linux_config_backend.py': 'b521fe01a23a6539a27810a92d48702079ae96321a41dd40f1518c4ff7a168ce', 'drills/linux/L02/l02_linux_evidence.py': 'f1be95bdc198e346209aa8ac3e7b37260654b08080336fb61edf5b6d6ee12bcd', 'drills/linux/L02/l02_linux_inspect.py': '6614d7e15b1d93ee9a14a2ddcdfa4809bc7bc5c92db3e2d559019fdb32e4c8f4', 'drills/linux/L02/l02_linux_journal.py': '82ddac3719b4a550007bc4806bae15a9c66ee7af3e12a12524939a8dfc0c239b', 'drills/linux/L02/l02_policy.py': '1f0256043cd16b373673c088740581fec810fa1db0d600fdcd91a256fa0b5445', 'drills/linux/L02/l02_prepare.py': '365e218526f66c7a305572030184fe0e92132a45e3e30b4b71a1d17c2739200f', 'drills/linux/L02/l02_watchdog_arm.py': '642841082d4970d6716346774998923c3b86ad4301d5c504a6c7f1fe0d4a3026', 'drills/linux/L02/l02_watchdog_helper.py': '0556e8b476e8844eefcdfcf224c8c497b41237c2fd3a1d31de230df2defba474', 'scripts/install_l02.py': '452eeacd45f2f6cc8c648e982c918c4b9efd70543f0de4b9a3dbd410edf0c43c', 'drills/linux/L02/recovery-v2/l02_audit.py': 'fbed2c8254298d2a1a949ba67445729934edf3ab81851d9b6f7c88878094683f', 'drills/linux/L02/recovery-v2/l02_cli.py': '553d98696b7b57f15619681d381c2b7e445fed2dfce6857d62c7fcc2a26a87ab', 'drills/linux/L02/recovery-v2/l02_config_lifecycle.py': 'a0cd65197f4411340eba0a133096e477212f880e08729e9ad372c1faa905c4bc', 'drills/linux/L02/recovery-v2/l02_initialize.py': 'f4b9dce0af162aa4dd7b46e7baffed02690cda71d918435b7e9bd15df8999a59', 'drills/linux/L02/recovery-v2/l02_isolated.py': '73b1d0119f2e25b807ae6555ff6aaa5196865aa89280fbbf68917944b1aecedc', 'drills/linux/L02/recovery-v2/l02_journal_avc.py': '9b1433956277e122134d536adab232b92f7589f6b4d27715c850518c923f1d8e', 'drills/linux/L02/recovery-v2/l02_linux_config.py': 'e20aa533d9151ca868c2c14ecc46f3914888f2a1cee7c5969bde95d9c6e66078', 'drills/linux/L02/recovery-v2/l02_linux_config_backend.py': 'b521fe01a23a6539a27810a92d48702079ae96321a41dd40f1518c4ff7a168ce', 'drills/linux/L02/recovery-v2/l02_linux_evidence.py': 'f1be95bdc198e346209aa8ac3e7b37260654b08080336fb61edf5b6d6ee12bcd', 'drills/linux/L02/recovery-v2/l02_linux_inspect.py': '6614d7e15b1d93ee9a14a2ddcdfa4809bc7bc5c92db3e2d559019fdb32e4c8f4', 'drills/linux/L02/recovery-v2/l02_linux_journal.py': '82ddac3719b4a550007bc4806bae15a9c66ee7af3e12a12524939a8dfc0c239b', 'drills/linux/L02/recovery-v2/l02_policy.py': '1f0256043cd16b373673c088740581fec810fa1db0d600fdcd91a256fa0b5445', 'drills/linux/L02/recovery-v2/l02_prepare.py': '55188b443644f17e5632074df20e1e1a7f8deea4215b21e962df73a9e5015bff', 'drills/linux/L02/recovery-v2/l02_watchdog_arm.py': 'ab58c9c75415c4cc643fde355e8996c68948fa0aedf479a4f6df6711e7fdacc8', 'drills/linux/L02/recovery-v2/l02_watchdog_helper.py': 'e03d4bdbf157f629603202d6a3e2b83fbebf0f8b425ad2e1f1108a73d0f5d52d', 'scripts/install_l02_v2.py': '154b2f841fd187ece446d54e9770ca9ffe0fcc7e5f6acab3a3d007dd75a5f7e1', 'drills/linux/L04/controller.py': '795ee1a568148b6c58975a90b18f9dcb67226d646dfce83a58220e045b61255a', 'drills/linux/L04/service.py': 'e1c2b9ad03adf59f3af4052c931ebe08630c407c82e0ac90bfd1366a4b3cd9d0', 'scripts/install_l04.py': '0af595d5732b23727aca348da08d00b0005ba8129df61d79f729c85f2c6f4c39', 'drills/mysql/M01/m01_core.py': 'a86235b38a7f26713b819832b42b2eb0b2d6b280b69e528d9e91b64dbc31747d', 'drills/mysql/M01/m01_owned.py': '8b40779dd53458876a32d8312714b071ce186e9788b878fb263dbafb99fbc79f', 'drills/mysql/M01/m01_watchdog.py': 'a546052e9bea13ff0c8c8781e9ea317ee788753503ff1d896639347aa07342df', 'scripts/install_m01.py': 'cf77d8732efadf0e97b45f1d89efd84daee4b0a0d09790cae6f45f27ac8fe757', 'drills/mysql/M02/m02_deadlock.py': '5d41a8b7feb577b22a358f3497e1a4eb1c53669a1fbf179a49ca9add16c065c9', 'drills/mysql/M02/m02_launcher.py': '3d6d8fad99fe5dd0e9ddc85450cb4bb94ae835053cd325d587a9066a418eb11d', 'scripts/install_m02.py': '567ff741ecbafb40607fbbccabc75c9837f9a7b71b1e359476232344a185cc6b', 'experimental/m03/mysql-v1/mysql_lifecycle.py': 'e1bc6b0895114652781b96c753760fff7ba83f82fad2c4e89f03d5a3de81b457', 'experimental/m03/mysql-v1/m04_controller.py': '46d4a9fa610dcfceadc2d3dc5f0bbb91f151b899644a332a59c456370496d9f9', 'experimental/m03/mysql-v1/m03_vm_probe.py': '0af53e4b3f18819699d4c68dc44f7a3cdc1ae4abe2696f2b661f92a4bfd53aac', 'scripts/install_m03_mysql.py': 'b640b8551f17f91f23c30910112d60638ed946fb2c76d96646d2089b5c9c50ab', 'experimental/n03-c01/n03_502.py': '8b527cad68557f7294be8580f58923c5e7a1563daf521b44087d19724bed6d5c', 'experimental/n03-c01/c01_control.py': 'a805272fe0550b7d87af0d2c2103b97172f0c6b334aeea6e5407f64f751946a6', 'experimental/n03-c01/n03_entry.py': '9594d3ebab440bfc5c3fc4c3f1aaf1f3bb5572f0b9e5cb41a1befd902f6f63a0', 'scripts/install_n03_c01.py': '76a4661ec95cf2c743a86cb58b2b6e8f8756954c8c2b1f655cb57c9205d88c3d', 'drills/network/N04/n04.py': '9c843ec997e0ab0de2053f56d3ef8445dc054646c916170960f55b16970ba10b', 'drills/network/N04/n04_lifecycle.py': '3b66b415d5c93087bf200d0a48de95c3eb913d8aa656c58e22b6487881d4362b', 'drills/network/N04/install_n04.py': '8cf0456b49051d46bc9d9e99d922f2cd677a7e3d67b7dd6b421370b81c3354e0', 'drills/network/N04/recovery-v2/n04.py': 'abff5af4494643834afc3dc0320e43c0d0661a6081ef50c779fc786f05007573', 'drills/network/N04/recovery-v2/n04_lifecycle.py': 'aae4b424880ab3fefcae2931712f34b44e92988060c4a98c6d8d55ba5c3227f3', 'drills/network/N04/recovery-v2/install_n04_v2.py': '71c0660571dbb4ebe1ae1c912045b43f0bb2034e28de90fc1bcd406498981172', 'drills/network/N01/n01.py': '954c3bc7f4e4c59156d7ae612ae107de76ee21204cf8333ce989a721cd5cc8a8', 'drills/network/N01/n01_watchdog.py': '183545f5421be32e41281be0ca340fe248436095902bf2b6969fce287c4976be', 'scripts/install_n01.py': 'cc29581c0782712179064416e63d195f22543fec60be6af2ade8b25a30e5b495', 'drills/network/N02/n02.py': 'a22e59d0217ab059b6c32f985094f074d8d553a273c2d3a2cc4065360d3120dc', 'scripts/install_n02.py': 'dc9a707fea286fed42ffe3fc16d3d2fa9cf6630710a96e40e6ca72a475ab2ab2', 'experimental/n03-c01/c01_control_v2.py': '29b84c493a889ff2ea6b624f23e3e98f6a15096eed5a648e676bed08d928b60a', 'scripts/install_c01_v2.py': '5f3d8d21eb998dbd3bd99b8a02462c0ad0b4362214983c656fed5c8e6360cd09'}
DEST=Path('/usr/local/libexec/opsdrill')
STATE=Path('/var/lib/opsdrill-runtime-install')
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
def need(v,message):
 if not v:raise ValueError(message)
def directory(path):
 for p in (path,*path.parents):
  s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'untrusted directory')
def checked(path,digest):
 directory(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:s=os.fstat(f.fileno());data=f.read(1048577)
 need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o022 and len(data)<=1048576 and hashlib.sha256(data).hexdigest()==digest,'input mismatch: '+str(path))
def preflight(source):
 need(os.geteuid()==0 and source.is_absolute(),'root and absolute source required');directory(source);directory(DEST)
 marker=Path('/etc/opsdrill-lab');checked(marker,'6fe0fdb8e748df6ccffcedafbfd758af95f14bf8194002664ad03a1c0f7c10de')
 p=subprocess.run(['/usr/bin/systemd-detect-virt','--vm'],env=ENV,capture_output=True,timeout=10)
 need(p.returncode==0 and p.stdout.strip()==b'vmware','VMware required')
 for name,digest in PINS.items():checked(source/name,digest)
 for task in TASKS:need(not os.path.lexists(DEST/task['target']),'destination exists: '+task['target'])
 if os.path.lexists(STATE):
  directory(STATE);need(not os.path.lexists(STATE/'run.json'),'prior installation record needs inspection')
def save(state,create=False):
 data=(json.dumps(state,sort_keys=True)+'\n').encode()
 if create:
  fd=os.open(STATE/'run.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);tmp=None
 else:fd,tmp=tempfile.mkstemp(prefix='.run-',dir=STATE)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fchmod(f.fileno(),0o600);os.fsync(f.fileno())
 if tmp is not None:os.replace(tmp,STATE/'run.json')
 d=os.open(STATE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(d);os.close(d)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',required=True,type=Path);p.add_argument('--apply',action='store_true');args=p.parse_args()
 preflight(args.source_root)
 print('Verified protected inputs and absent destinations:',len(PINS),'files,',len(TASKS),'runtimes',flush=True)
 if not args.apply:return 0
 directory(STATE.parent)
 try:STATE.mkdir(mode=0o700)
 except FileExistsError:pass
 directory(STATE);need(stat.S_IMODE(STATE.lstat().st_mode)==0o700,'state mode')
 lock=os.open(STATE/'install.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  st=os.fstat(lock);need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,'unsafe lock')
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);preflight(args.source_root)
  state={'status':'RUNNING','phase':'begin','completed':[]};save(state,create=True)
  for task in TASKS:
   state['phase']=task['name'];save(state);print('Install runtime:',task['name'],flush=True)
   cmd=['/usr/bin/python3','-I','-B',str(args.source_root/task['installer']),*[str(args.source_root/x) for x in task['args']]]
   p=subprocess.run(cmd,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=120)
   if p.returncode:raise ValueError('installer failed: '+task['name']+'; retained')
   state['completed'].append(task['name']);save(state)
  state['status']='DONE';save(state);print('All pinned runtime installers completed',flush=True)
 finally:os.close(lock)
 return 0
if __name__=='__main__':
 try:sys.exit(main())
 except (OSError,ValueError,subprocess.SubprocessError) as e:
  print('Runtime installation refused or incomplete:',type(e).__name__,str(e),file=sys.stderr);sys.exit(2)
