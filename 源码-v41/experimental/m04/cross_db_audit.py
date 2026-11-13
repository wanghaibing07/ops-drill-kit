"""Narrow auditor for two fixed synthetic INT tables and one-binlog PITR."""
import hashlib, struct, zlib

class AuditError(ValueError): pass
def require(value,message):
    if not value:raise AuditError(message)

def events(raw):
    require(isinstance(raw,bytes) and raw[:4]==b'\xfebin' and len(raw)<=8*1024*1024,'binlog magic or length')
    output=[];pos=4
    while pos<len(raw):
        require(pos+19<=len(raw),'short header')
        _,kind,server,size,nxt,_=struct.unpack('<IBIIIH',raw[pos:pos+19])
        require(size>=23 and pos+size<=len(raw) and nxt==pos+size,'event bounds')
        ev=raw[pos:nxt];require(zlib.crc32(ev[:-4])&0xffffffff==int.from_bytes(ev[-4:],'little'),'checksum')
        output.append((pos,nxt,kind,server,ev));pos=nxt
    return output

def table_map(body):
    require(len(body)>=10,'short table map');tid=int.from_bytes(body[:6],'little');n=body[8];j=9
    require(j+n+2<=len(body) and body[j+n]==0,'schema');db=body[j:j+n];j+=n+1
    n=body[j];j+=1;require(j+n+1<=len(body) and body[j+n]==0,'table');table=body[j:j+n];j+=n+1
    require(db in (b'cross_a',b'cross_b') and table==b'items' and tid>0,'table identity')
    require(body[j:j+4]==b'\x02\x03\x03\x00' and body[j+4:j+5]==b'\x00','table contract')
    return tid,db

def row(body,tid,kind):
    require(len(body)>=10 and int.from_bytes(body[:6],'little')==tid,'row table')
    extra=int.from_bytes(body[8:10],'little');i=8+extra
    require(extra>=2 and len(body)>=i+2 and body[i]==2 and body[i+1]&3==3,'row bitmap');i+=2
    if kind=='update':
        require(len(body)>=i+1 and body[i]&3==3,'update bitmap');i+=1
        require(len(body)==i+18 and body[i]==0 and body[i+9]==0,'update cardinality')
        require(struct.unpack('<II',body[i+1:i+9])==(1,100) and struct.unpack('<II',body[i+10:i+18])==(1,101),'update values')
    else:
        require(len(body)==i+9 and body[i]==0 and struct.unpack('<II',body[i+1:i+9])==(2,200),'delete values')

def begin(ev):
    body=ev[4][19:-4];require(len(body)>=13,'query length');n=body[8];p=13+int.from_bytes(body[11:13],'little')
    require(p+n+1<=len(body) and body[p+n]==0 and body[p:p+n] in (b'',b'cross_a',b'cross_b') and body[p+n+1:]==b'BEGIN','query')

def audit(raw,start,stop,end,expected_sha):
    require(all(type(x) is int for x in (start,stop,end)) and 4<=start<stop<end,'positions')
    require(hashlib.sha256(raw).hexdigest()==expected_sha,'binlog digest')
    all_events=events(raw);before=[x for x in all_events if start<=x[0]<stop];after=[x for x in all_events if stop<=x[0]<end]
    require([x[2] for x in before]==[34,2,19,31,19,31,16] and [x[2] for x in after]==[34,2,19,32,16],'transaction sequence')
    require(before[0][0]==start and before[-1][1]==stop and after[0][0]==stop and after[-1][1]==end and all(x[3]==211 for x in before+after),'transaction bounds')
    begin(before[1]);begin(after[1]);names=[]
    for i in (2,4):
        tid,db=table_map(before[i][4][19:-4]);row(before[i+1][4][19:-4],tid,'update');names.append(db)
    require(names==[b'cross_a',b'cross_b'],'schema sequence')
    tid,db=table_map(after[2][4][19:-4]);require(db==b'cross_b','delete schema');row(after[3][4][19:-4],tid,'delete')
    require(all_events[0][0]==4 and all_events[0][2]==15,'format event')
    return {'format_event':all_events[0][4],'row_events':b''.join(x[4] for x in before if x[2] in (19,31)),'commit_event':before[-1][4],'delete_start':stop}
