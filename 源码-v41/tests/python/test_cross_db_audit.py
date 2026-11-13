import hashlib,importlib.util,struct,unittest,zlib
from pathlib import Path
spec=importlib.util.spec_from_file_location('cross_db_audit',Path(__file__).resolve().parents[2]/'experimental/m04/cross_db_audit.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

def event(kind,pos,body=b'',server=211):
    size=19+len(body)+4;head=struct.pack('<IBIIIH',0,kind,server,size,pos+size,0);raw=head+body
    return raw+struct.pack('<I',zlib.crc32(raw)&0xffffffff)
def mapped(db,tid):return tid.to_bytes(6,'little')+b'\x01\x00'+bytes([len(db)])+db+b'\0\x05items\0\x02\x03\x03\x00\x00'
def row(tid,deleted=False):
    prefix=tid.to_bytes(6,'little')+b'\x01\x00\x02\x00\x02\xff'
    if deleted:return prefix+b'\0'+struct.pack('<II',2,200)
    return prefix+b'\xff\0'+struct.pack('<II',1,100)+b'\0'+struct.pack('<II',1,101)
def fixture():
    raw=b'\xfebin'; positions=[]
    def add(kind,body=b''):
        nonlocal raw
        positions.append(len(raw));raw+=event(kind,len(raw),body)
    add(15);start=len(raw);q=b'\0'*13+b'\0BEGIN'
    for kind,body in [(34,b''),(2,q),(19,mapped(b'cross_a',7)),(31,row(7)),(19,mapped(b'cross_b',8)),(31,row(8)),(16,b'\0'*8)]:add(kind,body)
    stop=len(raw)
    for kind,body in [(34,b''),(2,q),(19,mapped(b'cross_b',8)),(32,row(8,True)),(16,b'\0'*8)]:add(kind,body)
    return raw,start,stop,len(raw),positions

class CrossAuditTests(unittest.TestCase):
    def setUp(self):self.raw,self.start,self.stop,self.end,self.positions=fixture()
    def check(self,raw=None,stop=None):
        raw=self.raw if raw is None else raw
        return a.audit(raw,self.start,self.stop if stop is None else stop,self.end,hashlib.sha256(raw).hexdigest())
    def mutated(self,index,kind):
        raw=bytearray(self.raw);pos=self.positions[index];size=int.from_bytes(raw[pos+9:pos+13],'little');raw[pos+4]=kind
        raw[pos+size-4:pos+size]=struct.pack('<I',zlib.crc32(raw[pos:pos+size-4])&0xffffffff);return bytes(raw)
    def test_two_schemas_single_commit(self):
        result=self.check();self.assertEqual(result['delete_start'],self.stop);self.assertTrue(result['commit_event'])
    def test_missing_commit_and_split_rejected(self):
        for data in (self.mutated(7,2),self.mutated(5,16)):
            with self.subTest():
                with self.assertRaises(a.AuditError):self.check(data)
    def test_stop_inside_transaction_rejected(self):
        with self.assertRaises(a.AuditError):self.check(stop=self.positions[5])
    def test_checksum_or_truncation_rejected(self):
        raw=bytearray(self.raw);raw[-1]^=1
        with self.assertRaises(a.AuditError):self.check(bytes(raw))
        with self.assertRaises(a.AuditError):self.check(self.raw[:-1])

if __name__=='__main__':unittest.main()
