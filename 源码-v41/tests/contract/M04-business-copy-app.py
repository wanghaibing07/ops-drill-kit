"""Read-only preflight or isolated physical-copy app/PITR verification."""
import argparse,base64,hashlib,importlib.util,json,os,pwd,re,secrets,shutil,socket,stat,subprocess,sys,time,urllib.error,urllib.request,zlib
from dataclasses import asdict
from pathlib import Path

sys.dont_write_bytecode=True
p=argparse.ArgumentParser();p.add_argument('--vm-uuid',required=True);p.add_argument('--apply',action='store_true');a=p.parse_args()
def need(v,msg):
 if not v:raise RuntimeError(msg)
need(os.geteuid()==0 and Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==a.vm_uuid,'VM identity mismatch')
runtime=Path('/usr/local/libexec/opsdrill/m04-synthetic-v2');baseline=Path('/usr/local/libexec/opsdrill-clean-1196971f0799981c/baseline')
pins={'m04_controller.py':'46d4a9fa610dcfceadc2d3dc5f0bbb91f151b899644a332a59c456370496d9f9','continuation/mysql_live_identity.py':'c294cfa07973ef9342d4ca65147da14acbe6fa155ad29623edcda31fc48a42be','continuation/mysql_reset_gate.py':'eff466c8ad9dc5f7d2012a1b93aca33ffbb763d52ba8c39429f34ad7623178af'}
def protected(d):
 for x in (d,*d.parents):
  st=x.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,'untrusted directory')
def pinned(path,sha):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:st=os.fstat(f.fileno());raw=f.read(2_000_001)
 need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022 and hashlib.sha256(raw).hexdigest()==sha,'module pin mismatch')
 return raw
for d in (runtime,runtime/'continuation',baseline):protected(d)
for name,sha in pins.items():pinned(runtime/name,sha)
pinned(baseline/'mysql_import.py','de9a72de14b066488c4f6267dea7cac904408cfee937e5964c0fffa12cee4808')
pinned(baseline/'common.py','de57fdab833d35ed3ebc042ce1327ffe642004e61e7bbf2ae5fffeeefa4755a4')
sys.path[:0]=[str(runtime),str(runtime/'continuation'),str(baseline)]
import m04_controller as ctl
import mysql_live_identity as live
spec=importlib.util.spec_from_file_location('reviewed_primary_identity',baseline/'mysql_import.py');primary=importlib.util.module_from_spec(spec);spec.loader.exec_module(primary)
old='fd5303deba2c3d5a';oldbase=ctl.BASE/old;cont=oldbase/'continuation-d1afaa39aef1bb7f'
for d in (ctl.BASE,oldbase,cont):
 st=d.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o077,'unsafe old evidence')
for file in (oldbase/'state.json',cont/'result.json',cont/'state.json'):
 st=file.lstat();need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and not st.st_mode&0o022,'unsafe old evidence file')
oldraw=(oldbase/'state.json').read_bytes();oldstate=json.loads(oldraw);prior=json.loads((cont/'result.json').read_text());priorstate=json.loads((cont/'state.json').read_text())
need(prior.get('status')=='PASS' and prior.get('actor')=='agent' and prior.get('run_id')==old and prior.get('original_failure_state_sha256')==hashlib.sha256(oldraw).hexdigest(),'prior evidence mismatch')
need(priorstate.get('phase')=='STOPPED' and priorstate.get('candidate_phase')=='CONTINUATION_STOPPED','prior continuation not stopped')
def old_stopped():
 q=subprocess.run(['/usr/bin/systemctl','show',ctl.unit(old,'target'),'-p','ActiveState','-p','MainPID'],capture_output=True,text=True,timeout=10)
 need(q.returncode==0 and 'ActiveState=inactive' in q.stdout and 'MainPID=0' in q.stdout,'old target not stopped')
old_stopped();source=ctl.paths(old,'target')[1]
for d in (source,source.parent,source.parent.parent):
 st=d.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==pwd.getpwnam('mysql').pw_uid and not st.st_mode&0o077,'unsafe original datadir ancestry')
for proc in Path('/proc').iterdir():
 if proc.name.isdigit():
  try:args=(proc/'cmdline').read_bytes().split(b'\0')
  except OSError:continue
  need(('--datadir='+str(source)).encode() not in args,'old datadir in use')
log=source.parent/'server.log';st=log.lstat();need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size<20_000_000,'old log unsafe')
lines=log.read_text(errors='replace').splitlines();start=[i for i,x in enumerate(lines) if 'ready for connections' in x];stop=[i for i,x in enumerate(lines) if 'Shutdown complete' in x]
need(start and stop and stop[-1]>start[-1] and not (source/'mysqld-auto.cnf').exists(),'old target clean stop unproven')
mysql=pwd.getpwnam('mysql');devops=pwd.getpwnam('devops');files=[];dirs=[];total=0
for item in sorted(source.rglob('*')):
 st=item.lstat();relative=item.relative_to(source);need(st.st_uid==mysql.pw_uid and not stat.S_ISLNK(st.st_mode),'unsafe data object')
 if stat.S_ISDIR(st.st_mode):dirs.append((relative,stat.S_IMODE(st.st_mode)))
 else:
  need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,'unsafe data file');files.append((relative,st.st_size,stat.S_IMODE(st.st_mode)));total+=st.st_size
need(any(str(x[0])=='auto.cnf' for x in files) and shutil.disk_usage('/var/tmp').free>total+4*1024**3,'disk or UUID precondition failed')
mem=next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'));need(mem>400*1024,'memory precondition failed')
env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1','MYSQL_HISTFILE':'/dev/null'}
need(subprocess.run(['/usr/sbin/getenforce'],capture_output=True,env=env,timeout=10).stdout.strip()==b'Enforcing','SELinux not enforcing')
q=subprocess.run(['/opt/ops-drill-kit/.venv/bin/python','-I','-B','-c','import fastapi,uvicorn,pymysql'],user=devops.pw_uid,group=devops.pw_gid,extra_groups=[],env=env,capture_output=True,timeout=15);need(q.returncode==0,'application dependencies missing')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(url):
 try:r=opener.open(url,timeout=10)
 except urllib.error.HTTPError as exc:r=exc
 with r:
  raw=r.read(1000001);need(len(raw)<1000001,'HTTP response too large')
  try:return r.status,json.loads(raw)
  except (ValueError,UnicodeError):return r.status,{}
need(get('http://127.0.0.1:8080/ready')[0]==200,'business not ready')
payload={'app/main.py': ('c66ec5b96019ed02293d676f2d66aeada60ab51765fbe2a2f2bab0dca7b77126', 420, 'eJzFVntv2zYQ/9+fguAwSAJkOU5arPAmYG3itsHSJHMyDENbCLRE20RlUiUpO16R777jy5Zjd+gwYFMAh4973+/uyJaNkBoJ1ZtJsUQN0YuaTRFzx7ew7fl1s1lu1Ofa0c2I0qRhge41bF/eXqbo7f397fihpI1mgqdoQj+3VGnHQ5omA645PSs6rFK0mkpEFPJ37iA1W6kLf9gIUaeorIWi+0edTaE4adRCdNTxk7NC1WJ9qCzceHU7lqloeUUrKzGwvXJnt1aj+T03hlS9HjCgPHgfa6ZrmuMbWVH5piWywilaUakgFDk+yYbZCU4MS8Z4WbcV9brjPcePUjyxNun1nH05uhac9noVnaGC03VRTYtScE5LE/84GfUQfKWkFeWaEcNgUhoLlVG+YlLw9/h8Mr4YX99fvry6Ky4uJ+Pz+5vJH/hjggYI24z3G6LUWoA7VpqkupU8wCHz6mJ7Z76Ws4dCifIT1TkerIgcAKAGltj9ZuYSpzsGRWWOhYna3EQN0NF0roP2fOdGJimpCk0fdEx5KSrG5zlu9az/AieZVFqyJsYf5AeOk52cimgyJYp2VUGCygWRypgK/C+W02cdzWUrlZBlDQbkW3ftmcouWKnP7bpD70JRaLakkKf8LEXOUL9/nqK1ZJp2Dixv4hI4p/p4/hgk18FR2XyPtholYYp2EBlHwUtkGVpOVoTVZFrTKOlmz8rLuqp6vZ8N8AQv6AqiHEe2/toG+IxxrhoNlwpmzWsxBUjZwwM7udBHbZ203Hg/llLIp9aS2oRr43TRylvsgd6pwfgQ6tAI2J80fwYRJmyXgaEToeVmZ8dBX4kdEbVtC70Cc7YdbMfl4mWC7Mm3LtldKEcbi4NILlpdiTX3oXRd7O9D6ZpbkOp7na31A38g6l8P+lHTZ4yTuu6IOOirWzgAJuNoUBSiUZVkdT0wt/0lhRIrVZSi0KcYL1S5oEuSvya1os5R25Q9bSzdKBiFmeA9/w5dkSmCDrBiJUVTxiuFaiGaKSk//Yig3jfIcyo0E3INRUsrpBfQCOcLdD1n/CEL4POE4CuDuIdqQUI+uckWQmkbLMZRHA1Pf8hO4G8I/kSj0TBKDEv00N/qM6vIEAc5C8ApNPan4N6bfqat61YBSCsA5glAs6IaijGPrkHzzMB5H+G77Psi/RKpUjQ0GqFIQYurab+RoqRK9aGijbENq+ASmjmkCdZxp9uZL6rpnJQbILEQCOMxTo5hBlHIm109EeJgAUKOjdo4eex1oIIHEJlaL7ADgNsEkAevsAsMHiEsYA4g7LNvD7atuQ9vBPy4J9teqsEX+79g1aNXYxqnPYvDzQiSpXfdMxyjn9DwH+Ts9HSbM3zJV6QGCVYUurzARzrLmunFsS5u3htmv1+Wltoc+5ni6ex6n9KWqD3P6AMt4QUQH9ybD9+Nr2B8I1alaEklTDauC7MhS0Cbto8l8A69nty8c44o9Pvb8WQMHIC/7xVOj8rdhjVNDgmSgxMXojyYPKO6XACs9ttsHAbqu83dr1d2HKTo5s4vdhMt+fZ8PT852+XrIkyWzgj0OQuA+No4/bYqds88Wz62lr1wK/k9dhHHHyEM8ByJn5zujWJ7t19Edgx6cNt1KKH/C24BWUN8mO5/keZf6MavfuPMRPi/SP+RNuTiDZ0ovEd8b3rs/QVOdit+'), 'app/stage3_api.py': ('1b1de2012ad6402bcd8e54edc3ac71014663153487c017367833aa83a9f07334', 420, 'eJyNVm1v2zYQ/u5fcchQSCoUpWnarQ0gYK6ttEGTOJVdDEFbEIzEOMRkUiOpJtqw/74jKUXy4qzTB5s83vs9d+Te3l7OaLkvRdVCTddcUMNKoEXBtAYjwdwy0K3AP8MLWBq6ZnAEUpVMQUkN1cwke3t7E76ppTJQyTXqWPdbqSc3Sm5Qs7mt+DV05EvcTnqeut20+o/KM95QbWjNe8bp5WkuG8NUDB9Wq8vsvmC14VLE8Klhqu2UewVJ0Sgtle5l57wwM0fybLSuk2vZiJKVpJay6vneedolkmKwv7NKalZOJjYWjDLtg0rWzJw5WkiIoBtGSDRRzj1kenA1jCaTibeQwoUUDLcluwEi2B3RNoFHpJBCsMJGEkbHE8Cv5AoJUrUoZNMTSp0w8Z0rKb4EszybZxer0+nZksxP82y2WuRXwbfISRaKlUwYTq29Qc0BBN7YvsICM7VfU63vsHCBk1LMNEoMufMOhe7Mfo3g90TL4ndm0rEry9X0fXZEzq+Wn87IcjH7mK2Cb/EgpplKAwePdUNV2QfsfQgGxt6bdHA/sUzEsHsTMlHIElOeBo252X8TRInSRvE6DL6qryKIBj0Wg9eIwh1GR9aKW6oQqU7dm831q/GRg0hRoT/pAJnRuc8MMXzDsL7p0XDk/e3orwf6neKG7TqgjZGF3Gy4SU9opZk/iTqAoNfK9Amz+Omxsa7kNVbX0RyB30AHYQ1CGoey48EtyjWDvBHWg0wpqcIOCuCEaGUdb709VgYeRj1iR+0Q7oZsDJr/ydJXMdxRPiTmsI+jsP3zv+KoXc/1lonfupbponw6SHuSOEvhKH+9RaIFrfWtNL3psYkt/Fs1A/Mum8CwUuNGxjHwdB+PS7OrLMOA2S5KI+h3yit6XbGuIJ2HxEc6MoRu/OrHjp1IYXCAA/Pg++GBawCN0tbJimtDPMU39YYp7AJhCC+PgQuD2XAzNEySJMaY0sMYKqzqy7ev3v78y8u3r7smw0uBbQscjtgPX7hvxEssOLYFXr7YlkDuLltGtUOC7ri5fSq5QLXrxIH7QcKSu9nf8bn1NufQ6Qm7ZwUmL7SjLF/BKp9eLKez1eniAvJsOofFxdlVV4L/lM7OcA7DbPH5YhU+j2C6xOvSILxP8sW5vyA1/PYhy7Nx6tNnOoghHFHi6LEtryjtbd4wU9wilsLoS+COgm8/cu/Ruf16n51zRMh47Iad3PbfH2IJTKNjusFpYEiBA1rHwW6lNW2J1SJYFeMwt+8HQk3c1GW3/GFG4AnNi3ye5fDuCga1MM+Ws5iX7h/OTs9PV4AKFicny8yuRoN9/G0lfIApVsKuYR8OI3g+0KPHWh4XCWf8Rv+rSLTCYec4mXuqoP7ugj1v8cJ0wziGxbJbfGRtt/osON54rNsNQ8IBGnUNaP4J5tLNJnyVdFawQ8Bem9h1Bja0tS1hKBcwdBCUDCmVTh70+NdNwvz90D/s+ut0PI8gfKYjRK1paxaixSgZnj+9Nj/ctt5ooccQsXGlr18cxZ0PaTDfYSSIwL3SHqZ/N/7+CkalC45hq5BdNxz7hoktFtcMt/Zvu4TBQ227467+gaticOyr+ffkH1mvbxU='), 'app/n03_slow.py': ('2efb68db6aad54239b2c0fd42b85fae9947b87ff7ac20c712b41afeef9cdae99', 420, 'eJydVm1v2zYQ/q5fwfmLpMEvsuN0q1EBc2K1M6Zage1uLbZBYCTKIUqTAkUn8br89x0pS7FspdsqQAB5vDc+d7y7TqdzJXY8JWkXiVz1KEcFEw+I8DQXlCuUCYnUHUFMJJihhXeBFN0SsVOIPBKZ0IL0O52ORbe5kArhYs8TKqqtKKqVJNWqUFhVa63KyqTYohyrO0Zv0eHgBrZWeZJhkMhpdTK9mS/BOpFd9PN6fRM8JiRXVHDLkoaM/GcWx7ViyjNGN3cK6G8xK4g1C8Lpp3gVXEeL2Qqow5H1broO4tl8CTtt2LEHcscHIi9SSRnrce+it8GK2K51FUXreD57ZsylSAbFvhh8JpITNpCYp2I7uBVCxTQFiaWW+GBEPOv99GNsjK3XYbworXvoezSMPc+rfsuyUpIhbTHGiaL3xHEnFoIPgJ4m+r5IcLZHGEkw0xMPnKSGHQKFFaIFuseMpofQwVZ7g8Axg7cJl9am5L5Uq780S8EbUfRFTrhTAdLVlChezqJF+An9Xe6AHlyvo2VNWERvozCMfqv212EUfAyu3Vp5w5KxRiVJlJD70mamc8IBF9wGF80QB8cdfdpfxfMVWHZq0X6h4q1IiWtu1iDv4PK+j2rogaGhuPoqxe+jWdCmGHR44ofLS3dyJi6J2kl+SKnjgwaOtn5LfSXpZkOk3YrmKXiLaHEVRte/nIDZ1TeMs9Q/Q+kMXAMdz8QxtqdCrfAug3eOFmwiW1FaQK3POKP8sz4dvoj1Gd5NSwbqV+NxQ21B/yLoDWh95bWE4Kth0F+KFS5BkASngEEXNA1bgWAQLM3uou/8hvlvMLvFKrkDu5L0sx1jZuu0q7m1G0Xm0htPnN+93mvcy/78Mho/uRP7JcFnvh+fevV6/B/Ww9G/6gWm7sgDtsbuDw4pbFB6KZfMXb8BMlOgfHSoriZcsSKPyiE8ESnlG9/GRUKp7UJcJM0dt29OiFPRz1QmoETprkYec3jZBdJxVY7xsL+BXpE7F67bPSOO3XNdHBqiXxbPrYB7Ck6TmBfOOefhlg2NI5PddQ320Jvap17lps7y0+bwtZd0JKadqzU2Pcoox4y1lAd4EgkTBWnUhVbumrOuO8R0XOREq0BKAW34V8x25LD+AMhAWMzu6Mk2gm9ZP5Wtur8hClooNPfB/XAgZEpkMdAVE8JpBgmk+6AmxOVh1Qc3TNzCMFL3dkOEFARnCb+nUvBSdXSzmi3nYRgHi+lVGMQrqLO2eeL20EbQHXXOtvRZ4zKG0aY5YphKuStifUN/7I3hMRCFKfPthdCDEoxRh0QEX2rn/ofK0etnlSs9hZnSoBs6ZvpN7BHMJRyew8HM8XCzljty3tbxA6b1VNYvGCG50xiA3NMYfbFLl+wJMt3r4EMitjkjkHL2k9WaLOeD1j82RPJ5'), 'app/bounded_pool.py': ('d03cfece4535af585288a64e1d027d3488b1cb447bc191033494b04cf45b2747', 420, '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'), 'conf/orderguard-api.service': ('c9362aa8adfcf34cf6ff30f68aedd4aee3416c51be92fc2ec7cf81fcc6ee3983', 420, 'eJxtUMtuAjEMvPsr8gP7gB6oKuVARYs4lKIC4oA4hF0DFtkkcpyl+/dNH9wqy5LH4/FIs986kgPMMDZMQcg7/c4t8jwZbtWriTJdLdQauacGYXoSZO1Qbp6vpRg+owDs/+gDbIaAGj+xgW3Mhy32PkSYs0/hDnZZSe48I8ZGPA+68kFyx6Jlsra4ksBL/rDO3+Ufsip7dH11JFeFQS7eqaJTKdt7dsqEUHaG3FMeVFFcfBQ1Gk/KOtcoL4JnUY91XcMHxh8D74qTIZsY76s1NvoBtm8mXnVdjyew9Eu8rZh6snjGqIUTwjc2gpsu/GLYL1yWW3uAnXGC7fOgu2SFipSTuEf1BSQlgdQ='), 'conf/orderguard-nginx.conf': ('e5c190f4703e5917eca726d3679fc4daadabfbbb65c95927732a5a444606f513', 420, 'eJyVkU9PwzAMxe/7FD702qWFA9O4IsRuEyduUdSYtlIbFzv7J7TvTtJ0DE3AILlYeb9nyy+CvEWG9xmE07Xi0UF5czcvwi2Xi2JR3I+SjJx2pkfoqDJdQ+KTZKoKRXRHNaitYRUK5erW7RWxRa43hm2eoHnQ/mHybd+6Oprg/KrT69TGWt2gCRq85M/4tkHx+eoBMk61bi2YbmcOknhkJr4ydWTGoTvDLvniyr4lB2qKKp6BaX/QgxGBxvthqdTX5IopuTMZIR1SlNionJeXuqA/LfMU0oXsnPG30E8bX7GYLl+tI9+TRx0S5F8Nj8QhB4s2VpAlIua+168nKVZ/bLJm8gSZVA32eOmpyDmsfPxipI2HW7kkOHT8lMti0o+z4+wDoMLopg=='), 'conf/00-orderguard-timing.conf': ('bcf8e284fd4255874312fd762757737a07af6dceb0490e0c423fe7797709b1b7', 420, 'eJxtjU0OAiEMRveegjQms+EETjwLIVAZjFBsy8p4d38yUSa66/e9vvZCyZ2Ii1dDHJFT9xyd5pJrMijBNzyehaqZbsB47SjqcoQD7IdkoaAutKnXxoKo1y4vtE72c+j5BkfnnS30JsroiwtUK4bv3n8wCIzSqAr+Gltyn+bdAzW/XEg='), 'requirements.txt': ('4631d9507517d44bd1ea9f8b33e7b48d0f25700fc6d0809f97064415ab3cc836', 420, 'eJw9j0GOwjAMRfe5C1bTlMLGNwAJNAdAUephrEFO1JgRuT1OhUZe+dl++YkiWaPSstNWqCIOcIDBRWmcESfwI3iXHpx+EY/g4ejolagoZ7mv+VkQPQRb+Y5VY+F+7/1s4Mf7rZnNxotExADj4EpboignRBMH2P+DW8ordTrNRi/t3L6up263cuZeH6RKXTkdIDhLy3LfsdRCqafZJjB+Bjd6KUk1Xrdf9BTPP7Y3tsWwt/4NZ8pMHg=='), 'scripts/app_backup.py': ('ea1642b12cb8aa8fadd2c18e755bd3fa0393dee714ce48817817486005bafe56', 420, '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'), 'helper/proxy.py': ('d30cfebb00aafc316d15b22b3fe3da471571d503dbfd6f01a4d8f49570d282fd', 416, 'eJydVFFPGzEMfr9fEfpCooVTGYOHdvfAWJEQG0yUTZMQOoWcSyPS5JbkCv33cy650k08TKuqXGI7n+3Pdkaj0SfbmQYa0gK4Awc+OCUDnh1osSHBEmuAqAZMUGFz0CpjUBnQjngrnyCUo9GoUKvWukCs5x40yMCTjvsg4uK6KNp4HpYORKPMIw9qBUWhlQ9geBDuEa0bWCsJXBnbAO9Uwx9VU+G1EtXru8PJffGmxUq0VJnA6VtaxgrhPWBwxsYAy1aEZanhBT17mvyzwmsbfLWNrsykzAGxl9YB/cDQt2i0MlDF0MuVRTxrlKTs3dF4XKB6QYITxi/AUakVEsYmBYo2uJJnFZYkSeOR1DzyXccg6yoRVHamFfKJ7h+pfZ5MS2QlMmnbQDPb8+sv9fz67HJ2y7eS+ttsdnN2M/vMD99jvgivFmTA36twmTgInTNR5UOFLOhYGZp4H25EgqK4nNcX8+iD+lD6UK+QTkasI/mMNPO0Q6bZXvUH72zHVZ90jjJ9hixOz+vvVxc/X1M4u6zntzez06+MCE+6FikBseqp2p5KDyFyb7tAj9l0K5YWe1Jus5m+ZX+FXdznSVqhXJULxAfTpHpeKg3k7/J+HAqfoiGxRza8jnXre71MHxqB+d19/B8mPLJA0ryTRJl0KyOQRgRRoaJ0INf05Pj46CTfGOoQLXaYxB8dYo0mPajPDUVAe8h7htGYRmhNIwKCwouENhB6PZ85Zx3/IXQH/ZZNWpyMgiyUQfvNpJ8BjEiD8EBZUfx3+XDc1uAw2bQpH5RphlGbYvPJpX02WcDH/ZQmMXbaVmxPTsZsmhGSEKdwEOyUNpL9D5WLg5irHivXowgZyaGR+8xTzihjT7C1gjIdFK8D0rMk5K9O4bPwoNEeH4zqXGANWHZQSm0jhdOd669vy22/y91aDU8Gx6Pf9iXjjQDMpLp1HWBN0TiG+RsoavY9'), 'helper/server.py': ('ffe21f8aeae3593101ef8ab086e26632b19de803f9b21cdff5f066a4816ba55c', 416, 'eJyNklFr2zAUhd/9K4xfbIMQzbqxUdBDlqYMuq3BSWGjFKHYN4moLXm6UrL8+147djK6PczGSFc6Pnw6ukmSFMHEKnaA3jqoYtW2sdoqbdDHfgexRlsrTxtnRa3WcaW8WisEniRJpJvWOh9bZGjLF/AMjxjRx1vld5ycwPnsilnkYPbaWfOUfp1+ltPFQi4fHovZPH3OR5P22BzxV83CXpfWmWjjbNMzDfsNkTH0agvXUrU6iirYxKU1BkqvrclGsPwmImIfnBkt+aDKgtG/5YlUvGVaFA8/fhLV7H6+Sp9ZIPS/NKv5ciUfl/OCBFHcPa1CPFhX/Vv6bVrc9+KRTYwTVu6UQ8JIg998atbv08GwDA6tK2vyFWf8fg35rS79rJ+z4UTS6wZs8OKaOVDVufzADk57uNR51MXHpYGDrNbyEpuoVbOu1M0fQaZ0HnDboFyV5tEl8dPfQ/2/DoO+M6LcxSl8fhqyja7BWKGNz97m92W1Wsi7W+qPPBo6gi/B7cFlYzmzZqO3WX8w6hO2s0h5Tt595Ff0TlJW223HSSLx3RpgqiwBUdKyuFM1XQLd3As4FJM85y6Y7ISF4qmbUGe+AjmLHzA=')}
data={}
for name,(sha,mode,encoded) in payload.items():
 raw=zlib.decompress(base64.b64decode(encoded,validate=True));need(hashlib.sha256(raw).hexdigest()==sha,'payload pin mismatch');data[name]=(raw,mode)
print('Prior PITR, stopped source, runtime pins and resources verified; copy size',total,flush=True)
if not a.apply:sys.exit(0)
main_uuid=primary.identity();main_proc=primary.process_identity();ctl.setup();rid=secrets.token_hex(8);directory=ctl.BASE/rid;directory.mkdir(mode=0o700);lock=ctl.locked(directory)
boot,now=ctl.boot_context();state={'version':1,'run_id':rid,'phase':'PREPARING','primary_uuid':live.SENTINEL,'uuids':{},'attempted':[], 'boot_id':boot,'deadline_boottime':now+1200,'business_phase':'TEST_ONLY','candidate_phase':'COPYING','actor':'agent','source_run':old}
ctl.save(directory,state);print('New isolated application restore run',rid,flush=True)
api=proxy=listener=None;account_attempted=False;account_clean=True;bound=False;clean=False;result=None;record=None
def phase(x):state['candidate_phase']=x;ctl.save(directory,state);print('phase',x,flush=True)
def run(args,timeout=90):
 q=subprocess.run(args,capture_output=True,env=env,timeout=timeout);need(q.returncode==0,'subprocess failed: '+Path(args[0]).name);return q.stdout
def safe_verify():
 live.check(record,live.observe(rid,state,'target'));ctl.verify(rid,'target',live.SENTINEL,state['uuids']['target']);live.check(record,live.observe(rid,state,'target'))
def sql(statement,timeout=90):
 safe_verify();sock=ctl.paths(rid,'target')[2]
 cmd=['/usr/bin/mysql','--no-defaults','--host=localhost','--protocol=SOCKET','--socket='+str(sock),'--user=root','--batch','--raw','--skip-column-names','--skip-reconnect']
 q=subprocess.run(cmd,input=(statement+';\n').encode('ascii'),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=env,timeout=timeout)
 need(q.returncode==0 and len(q.stdout)<100_000_000,'SQL query failed');safe_verify();return q.stdout
def stop_process(proc,name):
 if proc is not None and proc.poll() is None:
  proc.terminate()
  try:proc.wait(timeout=15)
  except subprocess.TimeoutExpired:raise RuntimeError(name+' stop unconfirmed')
try:
 scratch=ctl.paths(rid,'target')[0].parent;scratch.mkdir(mode=0o700);os.chown(scratch,mysql.pw_uid,mysql.pw_gid);run(['/usr/bin/chcon','-t','mysqld_db_t',str(scratch)])
 target,datadir,_=ctl.paths(rid,'target');target.mkdir(mode=0o700);os.chown(target,mysql.pw_uid,mysql.pw_gid);run(['/usr/bin/chcon','-t','mysqld_db_t',str(target)])
 for name in ('tmp','run'):
  d=target/name;d.mkdir(mode=0o700);os.chown(d,mysql.pw_uid,mysql.pw_gid);run(['/usr/bin/chcon','-t','mysqld_var_run_t' if name=='run' else 'mysqld_db_t',str(d)])
 datadir.mkdir(mode=0o700);os.chown(datadir,mysql.pw_uid,mysql.pw_gid)
 for rel,mode in dirs:
  d=datadir/rel;d.mkdir(mode=mode);os.chown(d,mysql.pw_uid,mysql.pw_gid);os.chmod(d,mode)
 manifest=hashlib.sha256()
 for rel,size,mode in files:
  fd=os.open(source/rel,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);outfd=os.open(datadir/rel,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode);h=hashlib.sha256()
  with os.fdopen(fd,'rb') as f,os.fdopen(outfd,'wb') as out:
   before=os.fstat(f.fileno());need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==size,'source changed before copy')
   for block in iter(lambda:f.read(1024*1024),b''):h.update(block);out.write(block)
   after=os.fstat(f.fileno());need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'source changed during copy')
   out.flush();os.fchown(out.fileno(),mysql.pw_uid,mysql.pw_gid);os.fchmod(out.fileno(),mode);os.fsync(out.fileno())
  h2=hashlib.sha256()
  with (datadir/rel).open('rb') as f:
   for block in iter(lambda:f.read(1024*1024),b''):h2.update(block)
  need(h.digest()==h2.digest(),'copy checksum mismatch');manifest.update(str(rel).encode()+b'\0'+str(size).encode()+b'\0'+h.digest())
 need(not os.path.lexists(datadir/'.opsdrill-copy-origin-uuid.cnf'),'copy UUID archive exists')
 os.rename(datadir/'auto.cnf',datadir/'.opsdrill-copy-origin-uuid.cnf');run(['/usr/bin/chcon','-R','-t','mysqld_db_t',str(datadir)],120)
 old_stopped();state['copy_manifest_sha256']=manifest.hexdigest();phase('STARTING_COPY');ctl.launch(rid,'target',False,directory,state)
 deadline=time.monotonic()+45
 while True:
  try:identity=ctl.verify(rid,'target',live.SENTINEL);break
  except (ctl.SafetyError,OSError):
   if time.monotonic()>=deadline:raise
   time.sleep(.3)
 need(identity.lower()!=main_uuid.lower() and identity.lower() not in {x.lower() for x in oldstate['uuids'].values()},'database UUID collision')
 state['uuids']['target']=identity;state['phase']='READY';ctl.save(directory,state)
 record=live.observe(rid,state,'target');live.check(record,live.observe(rid,state,'target'));state['candidate_identities']={'target':asdict(record)};ctl.save(directory,state);bound=True;phase('VERIFYING_COPY')
 need(sql('SELECT @@global.general_log,@@global.slow_query_log,@@global.log_bin').strip()==b'0\t0\t0','unexpected SQL logging')
 need(sql("SELECT COUNT(*) FROM information_schema.PLUGINS WHERE PLUGIN_TYPE='AUDIT' AND PLUGIN_STATUS='ACTIVE' AND PLUGIN_LIBRARY IS NOT NULL").strip()==b'0','audit plugin present')
 need(sql('SELECT COUNT(*) FROM mysql.component').strip()==b'0','component present')
 queries={'legacy_merchants':'SELECT id,name,created_at FROM orderguard.merchants ORDER BY id','legacy_orders':'SELECT id,merchant_id,amount,status,created_at FROM orderguard.orders ORDER BY id','stage3_merchants':'SELECT merchant_id,merchant_name,region,created_at FROM orderguard_stage3.merchants ORDER BY merchant_id'}
 for key,query in queries.items():need(hashlib.sha256(sql(query)).hexdigest()==prior['content_sha256'][key],'prior content digest mismatch')
 for table,digest in prior['schema_sha256'].items():need(hashlib.sha256(sql('SHOW CREATE TABLE '+table)).hexdigest()==digest,'schema digest mismatch')
 need(sql('SELECT COUNT(*) FROM orderguard_stage3.orders').strip()==b'500000','restored count mismatch')
 need(sql('SELECT COUNT(*) FROM orderguard_stage3.orders WHERE merchant_id=88').strip()==b'25000','merchant count mismatch')
 expected=sql('SELECT HEX(order_no),merchant_id,user_id,order_status,amount_cents,HEX(pay_channel) FROM orderguard_stage3.orders WHERE merchant_id=88 ORDER BY created_at DESC,id DESC LIMIT 20').decode('ascii').splitlines()
 need(len(expected)==20,'insufficient expected rows')
 account='app_restore_'+secrets.token_hex(8);marker=secrets.token_hex(32);need(re.fullmatch(r'app_restore_[0-9a-f]{16}',account),'account name invalid')
 need(sql("SELECT COUNT(*) FROM mysql.user WHERE User='"+account+"' AND Host='localhost'").strip()==b'0','test account exists')
 state['test_account']={'name':account,'status':'CREATE_ATTEMPTED'};ctl.save(directory,state);account_attempted=True;account_clean=False
 sql("CREATE USER '"+account+"'@'localhost' IDENTIFIED BY '"+marker+"'; GRANT SELECT ON `orderguard`.`orders` TO '"+account+"'@'localhost'; GRANT SELECT ON `orderguard_stage3`.`orders` TO '"+account+"'@'localhost'")
 grants=sql("SHOW GRANTS FOR '"+account+"'@'localhost'").decode().splitlines()
 need(len(grants)==3 and sum(x.startswith('GRANT USAGE ON *.* TO ') for x in grants)==1 and sum(x.startswith('GRANT SELECT ON `orderguard`.`orders` TO ') for x in grants)==1 and sum(x.startswith('GRANT SELECT ON `orderguard_stage3`.`orders` TO ') for x in grants)==1,'grants differ')
 lab=Path('/var/tmp')/('opsdrill-business-app-'+secrets.token_hex(8));lab.mkdir(mode=0o750);os.chown(lab,0,devops.pw_gid);os.chmod(lab,0o750)
 (lab/'.opsdrill-lab').write_text('ops-drill-kit\n',encoding='ascii')
 for x in ('source','backups','restores'):(lab/x).mkdir(mode=0o700)
 os.chown(lab/'restores',0,devops.pw_gid);os.chmod(lab/'restores',0o750)
 names=[x for x in data if x.startswith('app/') or x.startswith('conf/') or x=='requirements.txt']
 def write(path,raw,mode,gid=0):
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
  with os.fdopen(fd,'wb') as f:f.write(raw);os.fchown(f.fileno(),0,gid);os.fchmod(f.fileno(),mode);f.flush();os.fsync(f.fileno())
 for name in names:
  raw,mode=data[name];path=lab/'source'/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);write(path,raw,mode)
 write(lab/'app_backup.py',data['scripts/app_backup.py'][0],0o600)
 spec=importlib.util.spec_from_file_location('reviewed_backup',lab/'app_backup.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 backup=mod.backup(lab,'source','backups/run',names);restored=mod.restore(lab,'backups/run','restores/run')
 for name in names:need(hashlib.sha256((restored/name).read_bytes()).digest()==hashlib.sha256(data[name][0]).digest(),'restored app digest mismatch')
 for d in (restored,restored/'app'):os.chown(d,0,devops.pw_gid);os.chmod(d,0o750)
 write(lab/'proxy.py',data['helper/proxy.py'][0],0o640,devops.pw_gid);write(lab/'server.py',data['helper/server.py'][0],0o640,devops.pw_gid)
 sock=ctl.paths(rid,'target')[2];st=sock.lstat();need(stat.S_ISSOCK(st.st_mode),'target socket missing')
 ps=lab/'proxy.sock';proxy=subprocess.Popen(['/usr/bin/python3','-I','-B',str(lab/'proxy.py'),str(ps),str(sock),str(st.st_dev),str(st.st_ino),str(devops.pw_uid),str(devops.pw_gid)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,start_new_session=True)
 deadline=time.monotonic()+10
 while not ps.exists():need(proxy.poll() is None and time.monotonic()<deadline,'proxy startup failed');time.sleep(.1)
 st=ps.lstat();need(stat.S_ISSOCK(st.st_mode) and st.st_uid==0 and st.st_gid==devops.pw_gid and stat.S_IMODE(st.st_mode)==0o660,'proxy identity mismatch')
 listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM);listener.bind(('127.0.0.1',0));listener.listen(16);port=listener.getsockname()[1]
 appenv=dict(env,LAB_APP_SOURCE=str(restored),LAB_PROXY_SOCKET=str(ps),LAB_TEST_USER=account,LAB_TEST_MARKER=marker,LAB_HTTP_FD=str(listener.fileno()))
 api=subprocess.Popen(['/opt/ops-drill-kit/.venv/bin/python','-I','-B',str(lab/'server.py')],user=devops.pw_uid,group=devops.pw_gid,extra_groups=[],pass_fds=(listener.fileno(),),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=appenv,start_new_session=True)
 listener.close();listener=None;url='http://127.0.0.1:'+str(port);deadline=time.monotonic()+15
 while True:
  need(api.poll() is None and proxy.poll() is None and time.monotonic()<deadline,'application startup failed')
  try:
   code,obj=get(url+'/health')
   if code==200 and obj.get('status')=='ok':break
  except (OSError,urllib.error.URLError):time.sleep(.1)
 need(get(url+'/ready')[0]==200,'restored application not ready')
 code,body=get(url+'/api/v1/orders?merchant_id=88&page=1&page_size=20');need(code==200 and body.get('total')==25000 and len(body.get('items',[]))==20,'order API mismatch')
 actual=['\t'.join((x['order_no'].encode().hex().upper(),str(x['merchant_id']),str(x['user_id']),str(x['order_status']),str(x['amount_cents']),x['pay_channel'].encode().hex().upper())) for x in body['items']]
 need(actual==expected,'API rows differ from restored database')
 need(get('http://127.0.0.1:8080/ready')[0]==200,'primary readiness changed')
 result={'status':'PASS','actor':'agent','run_id':rid,'source_run':old,'source_continuation':'continuation-d1afaa39aef1bb7f','source_result_sha256':hashlib.sha256((cont/'result.json').read_bytes()).hexdigest(),'copy_manifest_sha256':state['copy_manifest_sha256'],'restored_app_files':len(names),'app_manifest_sha256':hashlib.sha256((backup/'manifest.json').read_bytes()).hexdigest(),'app_lab_directory':str(lab),'total_orders':500000,'merchant_88_orders':25000,'http_orders':200,'http_ready':200,'matched_page_rows':20,'scope':'restored app files connected through isolated adapter to a physical copy of the previously recovered synthetic business database; prior PITR was a controlled continuation; not a coordinated production snapshot'}
finally:
 if listener is not None:listener.close()
 stop_process(api,'app');stop_process(proxy,'proxy')
 if account_attempted:
  try:
   sql("DROP USER IF EXISTS '"+account+"'@'localhost'")
   need(sql("SELECT COUNT(*) FROM mysql.user WHERE User='"+account+"' AND Host='localhost'").strip()==b'0','test account still exists')
   state['test_account']={'name':account,'status':'ABSENT'};ctl.save(directory,state);account_clean=True
  except Exception:print('account cleanup unconfirmed; preserve instance and ledger',flush=True)
 if bound and account_clean:
  try:
   safe_verify();state['phase']='STOPPING';ctl.save(directory,state);ctl.stop_one(rid,'target');state['phase']='STOPPED';state['candidate_phase']='STOPPED';ctl.save(directory,state);clean=True
  except Exception:print('isolated stop unconfirmed; preserve ledger',flush=True)
 os.close(lock)
if result is None or not clean or not account_clean:raise RuntimeError('combined restore or identity-bound cleanup incomplete')
need(primary.identity()==main_uuid and primary.process_identity()==main_proc,'primary identity changed')
need(get('http://127.0.0.1:8080/ready')[0]==200,'primary readiness changed');old_stopped()
result['cleanup']='PASS';result['business_ready_after']=200
with (directory/'app-business-result.json').open('x',encoding='utf-8') as f:json.dump(result,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
print('Restored application and 500000-row PITR copy PASS; result',directory/'app-business-result.json',flush=True)
