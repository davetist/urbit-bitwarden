"""Minimal test-harness noun codec. Not part of the server."""
def atom(x):return x if isinstance(x,int) else int.from_bytes(x.encode(),'little')
def cell(*xs):
    out=xs[-1]
    for x in reversed(xs[:-1]):out=(x,out)
    return out

def jam(noun):
    bits=0;pos=0
    def write(value,length):
        nonlocal bits,pos
        bits |= value<<pos;pos+=length
    def mat(a):
        if not a:write(1,1);return
        b=a.bit_length();c=b.bit_length()
        write(1<<c,c+1);write(b-(1<<(c-1)),c-1);write(a,b)
    def encode(n):
        if isinstance(n,tuple):write(1,2);encode(n[0]);encode(n[1])
        else:write(0,1);mat(atom(n))
    encode(noun)
    return bits.to_bytes((pos+7)//8,'little')

def scan_atoms(data, visit):
    """Iteratively decode jam atoms, validating backward references and framing.

    Shared cells need not be reconstructed: each literal atom is visited once.
    """
    pos=0;end=len(data)*8;nodes=set();pending=1;atoms=0
    def read(n):
        nonlocal pos
        if pos+n>end:raise ValueError('Truncated jam')
        start=pos//8;shift=pos%8
        v=int.from_bytes(data[start:(pos+n+7)//8],'little')>>shift
        pos+=n
        return v&((1<<n)-1) if n else 0
    def rub():
        zeros=0
        while read(1)==0:
            zeros+=1
            if zeros>64:raise ValueError('Invalid jam length')
        if zeros==0:return 0
        length=(1<<(zeros-1))+read(zeros-1)
        return read(length)
    while pending:
        at=pos;tag=read(1);pending-=1
        if tag==0:
            v=rub();nodes.add(at);atoms+=1;visit(v)
        elif read(1)==0:
            nodes.add(at);pending+=2
        else:
            ref=rub()
            if ref>=at or ref not in nodes:raise ValueError('Invalid jam back reference')
    if any(data[(pos+7)//8:]):raise ValueError('Nonzero trailing jam data')
    return atoms
