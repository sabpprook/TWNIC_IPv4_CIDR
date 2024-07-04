import requests
from bs4 import BeautifulSoup
from datetime import datetime

def Get_TWNIC_Html():
    r = requests.get('https://rms.twnic.tw/help_ipv4_assign.php')

    if r.status_code != requests.codes.ok:
        return
    
    open('TWNIC.html', 'w', encoding='utf-8').write(r.text)

def Parse_Html(file):
    html = BeautifulSoup(open(file, encoding='utf-8').read())
    trs = html.select('table tr')[1:]

    rules = []

    for tr in trs:
        tds = tr.select('td')[3:]
        ips = tds[0].text.split(' - ')

        start = ips[0]
        end = ips[1]
        range = int(tds[1].text)

        rules.append({
            'start': start,
            'end': end,
            'range': range,
            'start_uint': IP2Uint(start),
            'end_uint': IP2Uint(end),
        })

    rules = sorted(rules, key=lambda elm: elm.get('start_uint'))

    return rules

def Minify_Rules(rules: list):
    i = 0
    while (i < len(rules) - 1):
        r1 = rules[i]
        r2 = rules[i + 1]
        
        if r1['end_uint'] + 1 == r2['start_uint']:
            r2['start'] = r1['start']
            r2['start_uint'] = r1['start_uint']
            r2['range'] += r1['range']
            rules.remove(r1)
            i -= 1
        
        i += 1

    return rules

def Get_CIDR(rules: list):
    cidrs = []

    for line in rules:
        start = line['start']
        range = line['range']

        while (range > 0):
            start_uint = IP2Uint(start)
            free = FreeSize(start_uint)
            padding = PaddingSize(free, range)
            cidr = CIDR(start, padding)
            cidrs.append(cidr)

            range -= padding
            if range > 0:
                start = UInt2IP(start_uint, padding << 8)

    return cidrs

def IP2Uint(ip: str):
    t = ip.split('.')
    i1 = int(t[0]) << 24
    i2 = int(t[1]) << 16
    i3 = int(t[2]) << 8
    i4 = int(t[3])
    return i1 + i2 + i3 + i4

def UInt2IP(ip, offset = 0):
    ip = (ip + offset)
    i1 = (ip >> 24) & 255
    i2 = (ip >> 16) & 255
    i3 = (ip >> 8) & 255
    i4 = ip & 255
    return f'{i1}.{i2}.{i3}.{i4}'

def FreeSize(ip):
    bin = "{0:b}".format(ip)
    offset = len(bin) - (bin.rfind('1') + 1) - 8
    return 1 << offset

def PaddingSize(free, range):
    if (free <= range):
        return free

    if ((range & (range - 1)) == 0):
        return range

    cnt = 0
    while (range > 1):
        cnt += 1
        range >>= 1

    return 1 << cnt

table = {
    1: 24,
    2: 23,
    4: 22,
    8: 21,
    16: 20,
    32: 19,
    64: 18,
    128: 17,
    256: 16,
    512: 15,
    1024: 14,
    2048: 13,
    4096: 12,
    8192: 11,
    16384: 10,
    32768: 9,
    65536: 8,
}

def CIDR(ip, size):
    return f'{ip}/{table[size]}'

if __name__ == '__main__':
    Get_TWNIC_Html()
    rules = Parse_Html('TWNIC.html')
    rules = Minify_Rules(rules)
    cidrs = Get_CIDR(rules)
    text = '\n'.join(cidrs)
    today = datetime.today().strftime('%Y-%m-%d')

    md = f'# TWNIC_IPv4_CIDR\n### 更新日期: {today}\n```\n{text}\n```'
    open('README.md', 'w', encoding='utf-8').write(md)

    exit(0)
