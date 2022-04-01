
import json
from time import sleep
from tokenize import String
from urllib import request,parse
import requests
import hashlib
from pysafebrowsing import SafeBrowsing
from requests.auth import HTTPBasicAuth
import ipaddress
import urllib.parse
import pathlib
import os


def main():
    print("-----------------------------------------------------------");
    print("WELCOME TO SECURITY TOOL!");
    print("-----------------------------------------------------------");
    print("Use this tool to find out the security posture of an IP Address or URL/Domain and to get some information about your target");
    print("Security Tool searchs in more than 20 blacklists and uses several online tools to obtain all the information on the IP/Url/Domain ");
    print("First insert an IP or URL when requested, then you will get:")
    print("1)Information about the target")
    print("2)security posture of the target")
    print("3) A propretary Security Score about the target ")
    print("4) OPTIONAL: a txt log file with all the ouptup about the target ")
    print("-----------------------------------------------------------");
    
    
    Ip_or_URL = input("Enter your IP or URL: ");
    wantlog=input("Do you want the output to be logged on a txt file?(yes/no): ");
    flag=0
    if wantlog=="yes":
        print("")
        print("The output will be logged in a txt file called SecurityToolLog.txt, located in the same directory of this Tool.")
        print("CAUTION: the txt log file will be overwritten at every run of this tool!")
        sleep(5);
        flag=1;
        print("")
    IPURL= list(Ip_or_URL);
    if(IPURL[0] >= '0' and IPURL[0] <= '9'):
        try:
            ip = ipaddress.ip_address(Ip_or_URL);
            print("You inserted an IP Address");
            IpLookup(Ip_or_URL,flag);
        except ValueError:
            print("The given IP address is not valid");
            exit;
        
    else:
        if (IPURL[0]=="h" and IPURL[1]=="t" and IPURL[2]=="t" and IPURL[3]=="p" and IPURL[4]=="s" and IPURL[5]==":"and IPURL[6]=="/"and IPURL[7]=="/") or (IPURL[0]=="h" and IPURL[1]=="t" and IPURL[2]=="t" and IPURL[3]=="p" and IPURL[4]==":" and IPURL[5]=="/"and IPURL[6]=="/"):
            print("You inserted an URL ");
            URLLookup(Ip_or_URL,flag);
        else:
            print("The URL is not valid: If you want to insert a Domain, put the full URL, then the tool will automatically cut it to a Domain.");
            exit;


def IpLookup(IP,flag):
    if os.path.exists(str(pathlib.Path(__file__).parent.resolve())+"/readme.txt"):
        os.remove(str(pathlib.Path(__file__).parent.resolve())+"/readme.txt")
    if flag==1:
        f_name=str(pathlib.Path(__file__).parent.resolve())+"/readme.txt"
        f=open(f_name, 'a');

    SECURITY_SCORE=100
    print("-----------------OSINT INFORMATIONS--------------------")
    print("")
    ####THREATCROWD IP####
    TCIP_response=requests.get("https://www.threatcrowd.org/searchApi/v2/ip/report/?ip="+IP);
    if TCIP_response.json()['response_code']=='1':
        p=input("Threatcrowd found resolutions for the given IP, do you want to see them(yes/no): ");
        if p=="yes":
            print("####THREATCROWD IP OUTPUT####");
            decodedResponse = json.loads(TCIP_response.text)
            print (json.dumps(decodedResponse, sort_keys=True, indent=4));  
            
    else:
        print("Threatcrowd hasn't found any resolution for the given IP")
    if flag==1: 
        f.write("####THREATCROWD IP OUTPUT####")
        print_log(flag,TCIP_response.text,f);
    sleep(1);
    print("")

    #### HACKER TARGET GEOIP ####
    HTG_response=requests.get("https://api.hackertarget.com/geoip/?q="+IP);
    if "error" not in HTG_response.text:
        p=input("Hacker Target Geoip has found the geographical position of the given IP, do you want to see them?(yes/no):")
        if p=="yes":
            print("####HACKER TARGET GEOIP OUTPUT####");
            print(HTG_response.text);
    else : 
        print("Hacker Target Geoip hasn't found the position of the given IP")
    if flag==1:
        f.write("####HACKER TARGET GEOIP OUTPUT####")
        print_log_txt_only(flag,HTG_response.text,f);
    sleep(1);
    print("")
    print("-----------------SECURITY POSTURE ANALYSIS--------------")

    ####MALTIVERSE IP####
    MaltiverseIP_response= requests.get("https://api.maltiverse.com/ip/"+IP);
    
    if 'blacklist' in MaltiverseIP_response.json():
        print("ALERT: the IP address was found through Maltiverse in at least one blacklist");
        p=input("Do you want to see the full output? (yes/no): ");
        if p=="yes":
            print("####### MALTIVERSE IP OUTPUT######");
            decodedResponse = json.loads(MaltiverseIP_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4));
        print("THE SECURITY SCORE IS DECREASING BY 20")
        SECURITY_SCORE=SECURITY_SCORE-20;
    elif 'limit' in MaltiverseIP_response.json():
        print("Maltiverse API rquest limit reached, try again in 24h");
    else :
        print("The Maltiverse search haven't produced any result") 
    if flag==1: 
        f.write("####MALTIVERSE IP OUTPUT####")
        print_log(flag,MaltiverseIP_response.text,f);
    sleep(1);
    print("")
    
    
    

    #### INTERNET STORM CENTER ####
    ISTC_response=requests.get("http://isc.sans.edu/api/ip/"+IP);
    if "<threatfeeds>" in ISTC_response.text:
        print("ALERT: the IP address was found related to some threats via Internet Storm Center in at least one blacklist")
        p=input("Do you want to see the full output? (yes/no): ");
        if p=="yes":
            print("####INTERNET STORM CENTER OUTPUT####");
            print(ISTC_response.text);
        print("THE SECURITY SCORE IS DECREASING BY 20")
        SECURITY_SCORE=SECURITY_SCORE-20;
    else :
        print("The Internet Storm Center search haven't produced any result");
    if flag==1: 
        f.write("####INTERNET STORM CENTER OUTPUT####")
        print_log_txt_only(flag,MaltiverseIP_response.text,f);
    sleep(1);
    print("")


    
    
    
    ####COIN BLOCKER LIST IP####
    CBLIP_response=requests.get("https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key=8d2082e8f770cd05fbfb82c6343638cfbee3567a&ip="+IP);
    if "error" not in CBLIP_response.json():
        if CBLIP_response.json()["data"]["report"]["blacklists"]["detections"]>0:
            p=input("ALERT:According to Coin Blocker List, the given IP is maliciuos and was found in "+str(CBLIP_response.json()["data"]["report"]["blacklists"]["detections"])+" engines. Do you want to see the full output?(yes/no):")
            if p=="yes":
                print("####COIN BLOCKER LIST IP OUTPUT####");
                print("TUTTO COMMENTATO PER NON SPRECARE CREDITI API, EVENTUALMENTE CON 12 USD COMPRO 25000 QUERY");
                decodedResponse = json.loads(CBLIP_response.text)
                print(json.dumps(decodedResponse, sort_keys=True, indent=4));
            print("THE SECURITY SCORE IS DECREASING BY 20")
            SECURITY_SCORE=SECURITY_SCORE-20;
        else:
            print("Coin Blocker List hasn't found the given IP in any engine.");
    else:
            print("Coin Blocker List hasn't found the given IP in any engine.");
    if flag==1: 
        f.write("####COIN BLOCKER LIST OUTPUT####")
        print_log(flag,CBLIP_response.text,f);
    sleep(1);
    print("")
    
    ####BLOCKLIST DE OUTPUT #####
    BL_response=requests.get("http://api.blocklist.de/api.php?ip="+IP);
    s1=BL_response.text.split("attacks: ",1)[1]; 
    s2=BL_response.text.split("reports: ",1)[1]; 
    l1=list(s1);
    l2=list(s2);
    if int(l1[0])>0 and int(l2[0])>0:
        print("ALERT: Blocklist de found "+l1[0]+" attacks and "+l2[0]+" reports related to thr given IP");
        print("THE SECURITY SCORE IS DECREASING BY 20")
        SECURITY_SCORE=SECURITY_SCORE-20;
    else:
        print("Blocklist hasn't found any threat realted to the given IP address");
    #print("####BLOCKLIST DE OUTPUT####");
    if flag==1: 
        f.write("####BLOCKLIST DE OUTPUT####")
        print_log_txt_only(flag,BL_response.text,f);
    sleep(1);
    print("")
    

    ####PHISHSTATS IP#####
    PSIP_response=requests.get("https://phishstats.info:2096/api/phishing?_where=(ip,eq,"+IP+")");
    if len(PSIP_response.json())!=0:
        p=input("ALERT: According to Phishstats your IP is related to phishing threat or is dangerous,do you want to see the full output?(yes/no):");
        if p=="yes": 
            print("####PHISHSTATS IP OUTPUT####");
            decodedResponse = json.loads(PSIP_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4)); 
        print("THE SECURITY SCORE IS DECREASING BY 20")
        SECURITY_SCORE=SECURITY_SCORE-20;
    else: 
        print("Phishstats hasn't found any threat related to the given IP")
    if flag==1: 
        f.write("####PHISHSTATS IP OUTPUT####")
        print_log(flag,PSIP_response.text,f);
    sleep(1);
    print("")
    

    ####OPEN PHISH IP####
    #opdb= pyopdb.OPDB(cfg_file=<CONFIG_PATH>)
    #print(pyopdb.check_url(opdb,"http://example.com/"))
    #print(pyopdb.check_ip(opdb, "8.8.8.8"))

    ####IP QUALITY SCORE IP####
    IQSIP_response=requests.get("https://ipqualityscore.com/api/json/ip/yrOKlKwtQgGpU7TlHfRjtmFeIbnUyP8t/"+IP);
    print("How to interpret the Fraud Score:")
    print("Fraud Scores <= 40 -low risk ");
    print("Fraud Scores >= 75 - suspicious - previous reputation issues or low risk proxy/VPN.");
    print("Fraud Scores >= 85 - high risk - recent abusive behavior over the past 24-48 hours.");
    if(IQSIP_response.json()['fraud_score']>=85):
        p=input("ALERT: According to IP Quality Score, the given IP is almost for sure dangerous, with a Fraud Score of "+str(IQSIP_response.json()['fraud_score'])+". Do you want to see the full output?(yes/no): ");
        if p=="yes":
            print("####IP QUALITY SCORE OUTPUT####");
            decodedResponse = json.loads(IQSIP_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4));
        print("THE SECURITY SCORE IS DECREASING BY 30")
        SECURITY_SCORE=SECURITY_SCORE-30;
    if(IQSIP_response.json()['fraud_score']>=75 and IQSIP_response.json()['fraud_score']<85):
        p=input("ALERT: According to IP Quality Score, the given IP is suspicious, with a Fraud Score of "+str(IQSIP_response.json()['fraud_score'])+". Do you want to see the full output?(yes/no): ");
        if p=="yes":
            print("####IP QUALITY SCORE OUTPUT####");
            decodedResponse = json.loads(IQSIP_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4));
        print("THE SECURITY SCORE IS DECREASING BY 20")
        SECURITY_SCORE=SECURITY_SCORE-20;
    if(IQSIP_response.json()['fraud_score']>40 and IQSIP_response.json()['fraud_score']<75):
        p=input("According to IP Quality Score, the given IP is not suspicious, with a Fraud Score of "+str(IQSIP_response.json()['fraud_score'])+". Do you want to see the full output?(yes/no): ");
        if p=="yes":
            print("####IP QUALITY SCORE OUTPUT####");
            decodedResponse = json.loads(IQSIP_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4));
        print("THE SECURITY SCORE IS DECREASING BY 10")
        SECURITY_SCORE=SECURITY_SCORE-10;
    if(IQSIP_response.json()['fraud_score']<=40 ):
        p=input("According to IP Quality Score, the given IP is safe, with a Fraud Score of "+str(IQSIP_response.json()['fraud_score'])+". Do you want to see the full output?(yes/no): ");
        if p=="yes":
            print("####IP QUALITY SCORE OUTPUT####");
            decodedResponse = json.loads(IQSIP_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4));
    else:
        print("IP Quality Score hasn't found anything related to the given IP")
    if flag==1: 
        f.write("####IP QUALITY SCORE OUTPUT####")
        print_log(flag,IQSIP_response.text,f);
    sleep(1);
    print("")
    

     ####META DEFENDER IP####
    url = "https://api.metadefender.com/v4/ip/"+IP
    headers = {
    "apikey": "909b1815323adff03705bd8b905fefb0"
    }
    MDIP_response = requests.request("GET", url, headers=headers);
    #"How to interpret the status:")
    #"0	Allowlisted: IP is listed by the source in their allowlist. Note: Not all sources provide allowlists.");
    #"1	Blocklisted: IP is listed by the source in their blocklist. Refer to the source for more information regarding their blocklist.")
    #"3	Failed to scan: The results could not be retrieved from our servers")
    #"5	Unknown: The source has not listed this IP address in either their blocklist or allowlist.")
    if "lookup_results" in MDIP_response.json():
        if MDIP_response.json()["lookup_results"]["detected_by"]>0:
            count=0;
            for source in MDIP_response.json()["lookup_results"]["sources"]:
                if source["status"]==1:
                    count=count+1;
            if count>0 :
                p=input("ALERT: According to Meta Defenfer, the given IP was found in: "+str(count)+" Blocklist. Do you want to see the full output?(yes/no):")
                if p=="yes": 
                    print("#### META DEFENDER IP OUTPUT####")
                    decodedResponse = json.loads(MDIP_response.text)
                    print(json.dumps(decodedResponse, sort_keys=True, indent=4));
                print("THE SECURITY SCORE IS DECREASING BY 20")
                SECURITY_SCORE=SECURITY_SCORE-20;
            else: 
                p=input("According to Meta Defender, the given IP wasn't found in any Blocklist. Do you want to see the full output?(yes/no):")
                if p=="yes": 
                    print("#### META DEFENDER IP OUTPUT####")
                    decodedResponse = json.loads(MDIP_response.text)
                    print(json.dumps(decodedResponse, sort_keys=True, indent=4));
        else:
            print("Meta Defender wasn't able to find anything related to the given IP");
    else:
        print("Meta Defender wasn't able to find anything related to the given IP");
    if flag==1: 
        f.write("####META DEFENDER IP OUTPUT####")
        print_log(flag,MDIP_response.text,f);
    sleep(1);
    print("")
         
    ####BOTSCOUT####
    BS_response=requests.get("http://botscout.com/test/?ip="+IP+"&key=rRTC5EvU83Q29Pt");
    if list(BS_response.text)[0]=="Y":
        print("ALERT: According to BotScout, the given IP is related to a bot, and was found in the database: "+BS_response.text.split("|",2)[2]+" times" )
        print("THE SECURITY SCORE IS DECREASING BY 20")
        SECURITY_SCORE=SECURITY_SCORE-20;
    else:
         print("BotScout was not able to find any information on the given IP");
    #print("####BOTSCOUT OUTPUT####")
    #print(BS_response.status_code);
    #print(BS_response.text);
    if flag==1: 
        f.write("####BOTSCOUT OUTPUT####")
        print_log_txt_only(flag,BS_response.text,f);
    sleep(1);
    print("")

    ####ABUSEIPDP####
    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
    'ipAddress': IP,
    }

    headers = {
    'Accept': 'application/json',
    'Key': '4c22ff5698bd6465ad8232b285ecc4dbcc1c879dcdd63c5b4891548131172635b489c3a853c37861'
    }

    AIPDP_response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    
    #Our confidence of abuse is a rating (scaled 0-100) of how confident we are, based on user reports, that an IP address is entirely malicious. So a rating of 100 means we are sure an IP address is malicious, while a rating of 0 means we have no reason to suspect it is malicious. Don't be disheartened if your report only increases this value by a few percentage points; the confidence rating is a very conservative value. Because this metric may be used as a basis to block connections, we take great care to only condemn addresses that a strong number of AbuseIPDB users testify against.
    #The confidence rating is determined by reports and their age. The base value is the natural logarithmic value of distinct user reports. All report weights decay with time. Confidence ratings for all reported addresses are recalculated daily to apply the time decay. Certain user traits can also slightly increase weight such as webmaster and supporter statuses.
    #The formula is carefully designed to ensure no one reporter can overpower the ratings. Only by working together can we build an effective net of trust.
    if AIPDP_response.json()["data"]["abuseConfidenceScore"]>=90:
        p=input("According to AbuseIPDB, the given IP is almost for sure malicious, with an abuse confidence score of: "+str(AIPDP_response.json()["data"]["abuseConfidenceScore"])+". Do you wan to see the full output?(yes/no):")
        if p=="yes":
        # Formatted output
            decodedResponse = json.loads(AIPDP_response.text)
            print("####ABUSEIPDP OUTPUT####")
            print (json.dumps(decodedResponse, sort_keys=True, indent=4))
    if AIPDP_response.json()["data"]["abuseConfidenceScore"]<90 and AIPDP_response.json()["data"]["abuseConfidenceScore"]>=50:
        p=input("ALERT:According to AbuseIPDB, the given IP is probably malicious, with an abuse confidence score of: "+str(AIPDP_response.json()["data"]["abuseConfidenceScore"])+". Do you wan to see the full output?(yes/no):")
        if p=="yes":
        # Formatted output
            decodedResponse = json.loads(AIPDP_response.text)
            print("####ABUSEIPDP OUTPUT####")
            print (json.dumps(decodedResponse, sort_keys=True, indent=4))
        print("THE SECURITY SCORE IS DECREASING BY 30")
        SECURITY_SCORE=SECURITY_SCORE-30;
    if AIPDP_response.json()["data"]["abuseConfidenceScore"]<50 and AIPDP_response.json()["data"]["abuseConfidenceScore"]>=10:
        p=input("ALERT:According to AbuseIPDB, the given IP may be malicious, with an abuse confidence score of: "+str(AIPDP_response.json()["data"]["abuseConfidenceScore"])+". Do you wan to see the full output?(yes/no):")
        if p=="yes":
        # Formatted output
            decodedResponse = json.loads(AIPDP_response.text)
            print("####ABUSEIPDP OUTPUT####")
            print (json.dumps(decodedResponse, sort_keys=True, indent=4))
        print("THE SECURITY SCORE IS DECREASING BY 20")
        SECURITY_SCORE=SECURITY_SCORE-20;
    if AIPDP_response.json()["data"]["abuseConfidenceScore"]<10 :
        p=input("According to AbuseIPDB, the given IP is probably safe, with an abuse confidence score of: "+str(AIPDP_response.json()["data"]["abuseConfidenceScore"])+". Do you wan to see the full output?(yes/no):")
        if p=="yes":
        # Formatted output
            decodedResponse = json.loads(AIPDP_response.text)
            print("####ABUSEIPDP OUTPUT####")
            print (json.dumps(decodedResponse, sort_keys=True, indent=4))
    else:
        print("AbuseIPDP wasn't able to find any usefull information on the given IP address");
    if flag==1: 
        f.write("####ABUSEIPDP OUTPUT####")
        print_log(flag,AIPDP_response.text,f);
    sleep(1);
    print("")
    

    ####FraudGuard####
    ### TOOL A PAGAMENTO, SCANDEZA IL 12 APRILE
    FG_response=requests.get('https://api.fraudguard.io/v2/ip/'+IP, verify=True, auth=HTTPBasicAuth('m0Qlr0sWvmQgRFdA', 'p9WdA8kxdif8ue14'))
    print("How to interpret the FraudGuard risk level output:")
    print(" 1= No Risk")
    print("2 = Spam or Website Abuse (excessive scraping, resource linking or undesired site automation)")
    print("3 = Open Public Proxy")
    print("4 = Tor Node")
    print("5 = Honeypot, Malware, Botnet or DDoS Attack")
    if "risk_level" in FG_response.json():
        if FG_response.json()["risk_level"]>"1":
            p=input("ALERT:Acording to FraudGuard the given IP is suspicious, with a risk level of: "+FG_response.json()["risk_level"]+". Do you want to see the full output?(yes/no):")
            if p=="yes":
                print("####FRAUDGUARD OUTPUT####")
                decodedResponse = json.loads(FG_response.text)
                print (json.dumps(decodedResponse, sort_keys=True, indent=4))
            if flag==1:
                f.write(json.dumps(decodedResponse, sort_keys=True, indent=4))
            print("THE SECURITY SCORE IS DECREASING BY 20")
            SECURITY_SCORE=SECURITY_SCORE-20;
        else:
            print("According to Fortiguard, there is no risk related to the given IP");
    else:
        print("FraudGuard API not working")
    if flag==1: 
        f.write("####FRAUDGUARD OUTPUT####")
        print_log(flag,FG_response.text,f);
    sleep(1);
    print("")    

    ####NEUTRINO API####
    
    url = 'https://neutrinoapi.net/ip-blocklist'
    params = {
   'user-id': 'vansonero',
   'api-key': 'EvWiXww0v0Q6fzxLf4wtI4DWnIgaPowlBxjaL0MDt0Hf8YDs',
   'ip': IP
    }
    NA_respone=requests.get(url=url,params=params);
    postdata = parse.urlencode(params).encode()
    req = request.Request(url, data=postdata)
    N_response = request.urlopen(req)
    N_result = json.loads(N_response.read().decode("utf-8"))
    count=0;
    for key in NA_respone.json():
        if NA_respone.json()[key]==True:
            count=count+1;
    if count>0:
        p=input("ALERT:According to Neutrino, the given IP address is malicious. Do you want to see the full output?(yes/no):")
        if p=="yes":
            print("####NEUTRINO OUTPUT####")
            decodedResponse = json.loads(NA_respone.text)
            print (json.dumps(decodedResponse, sort_keys=True, indent=4))
        print("THE SECURITY SCORE IS DECREASING BY 20")
        SECURITY_SCORE=SECURITY_SCORE-20;
    else:
        print("Neutrino hasn't found any threat related to the given IP");
    if flag==1: 
        f.write("####NEUTRINO OUTPUT####")
        print_log(flag,NA_respone.text,f);
    sleep(1);
    print("")
    
    ####IP REGISTRY####
    IR_response=requests.get("https://api.ipregistry.co/"+IP+"?key=9ogxendr7hszhb29");
    count=0;
    if 'security' in IR_response.json():
        for key in IR_response.json()["security"]:
            if IR_response.json()["security"][key]==True:
                count=count+1;
        if count>0:
            p=input("ALERT:According to IP Registry, the given IP address is malicious. Do you want to see the full output?(yes/no):")
            if p=="yes":
                print("####IP REGISTRY OUTPUT####")
                decodedResponse = json.loads(IR_response.text)
                print (json.dumps(decodedResponse, sort_keys=True, indent=4))
            print("THE SECURITY SCORE IS DECREASING BY 20")
            SECURITY_SCORE=SECURITY_SCORE-20;
        else:
            print("IP registry hasn't found any threat related to the given IP");
    else:
        print("IP registry hasn't found anything related to the given IP");
    if flag==1: 
        f.write("####IP REGISTRY OUTPUT####")
        print_log(flag,IR_response.text,f);
    print("")
    sleep(1)
    print("")
    print("---------------------------SECURITY SCORE RESULTS---------------------------")
    print("")
    print("")
    if SECURITY_SCORE==100:
        print("The Security Score of the given IP is 100")
        print("It means that, according to all the blacklists and sources implemented in this Tool, the given IP is safe and not malicious.")
        print("CAUTION: this is Tool provides a good indicator of security, BUT this doesn't mean that the given IP is for sure safe. Other analysis may be required ")
    elif SECURITY_SCORE>=80 and SECURITY_SCORE<100:
        print("The Security Score of the given IP is "+str(SECURITY_SCORE))
        print("It means that the given IP was found in one ( or maximum two) blacklist or tool, meaning that it may be malicious.")
    elif SECURITY_SCORE>=50 and SECURITY_SCORE<80:
        print("The Security Score of the given IP is "+str(SECURITY_SCORE))
        print("It means that the given IP was found in more blacklists and tool, indicating that it is probably malicious and related to a threat.")
    elif SECURITY_SCORE<50:
        if SECURITY_SCORE < 0 :
            SECURITY_SCORE=0;
        print("The Security Score of the given IP is "+str(SECURITY_SCORE))
        print("It means that the given IP was found in multiple blacklists and tools, meaning that it is for sure malicious and related to a threat.")

    print("")
    print("Thank you for using this Tool   -Alessandro Vannini")
    print("-----------------------------------------------------------------------------")
    if flag==1:
        f.close()

    
    

def URLLookup(URL,flag):
    if flag==1:
        f_name=str(pathlib.Path(__file__).parent.resolve())+"/readme.txt"
        f=open(f_name, 'a');
        f.truncate();
    SECURITY_SCORE=100
    print("-----------------OSINT INFORMATIONS--------------------")
    print("")

    ####THREATCROWD URL####
    l=list(URL);
    str1="";
    if l[0]=="h" and l[1]=="t" and l[2]=="t" and l[3]=="p" and l[4]=="s" and l[5]==":"and l[6]=="/"and l[7]=="/" :
        l.pop(7);
        l.pop(6);
        l.pop(5);
        l.pop(4);
        l.pop(3);
        l.pop(2);
        l.pop(1);
        l.pop(0);
    elif l[0]=="h" and l[1]=="t" and l[2]=="t" and l[3]=="p" and l[4]==":" and l[5]=="/"and l[6]=="/":
        l.pop(6);
        l.pop(5);
        l.pop(4);
        l.pop(3);
        l.pop(2);
        l.pop(1);
        l.pop(0);
    TCURL_response=requests.get("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="+str1.join(l));
    if TCURL_response.json()['response_code']=='1':
        p=input("Threatcrowd found resolutions for the given URL, do you want to see them(yes/no): ");
        if p=="yes":
            print("####THREATCROWD URL OUTPUT####");
            decodedResponse = json.loads(TCURL_response.text)
            print (json.dumps(decodedResponse, sort_keys=True, indent=4));  
    else:
        print("Threatcrowd hasn't found any resolution for the given URL") 
    if flag==1:
        f.write("####THREATCROWD URL OUTPUT####")
        print_log(flag,TCURL_response.text,f);
    sleep(1);
    print("")


    ##### URL SCAN.IO #####
    headers = {'API-Key':'a7111746-1110-490e-aae9-c98c955db0d2 ','Content-Type':'application/json'}
    data = {"url": URL, "visibility": "public"}
    US_response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    if US_response.json()['message']=='Submission successful':
        p=input("Urlscan.io found informations relative to the given URL, do you want to see them?(yes/no):")
        if p=="yes":
            print("####URLSCAN OUTPUT####");
            decodedResponse = json.loads(US_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4)); 
    if flag==1:
        f.write("####URLSCAN.IO OUTPUT####")
        print_log(flag,US_response.text,f);
    print("")
    sleep(1);

    ####BUILTWITH####
    BW_response=requests.get("https://api.builtwith.com/free1/api.json?KEY=7a2c3f13-187f-4c2f-b082-c5ec0cac4722&LOOKUP="+URL);
    if "Errors" not in BW_response.json():
        p=input("BuiltWith found information about the given URL technologies. Do you want to see them?(yes/no):");
        if p=="yes":
            print("####BUILTWITH OUTPUT####");
            decodedResponse = json.loads(BW_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4));

    else:
        print("BuiltWith hasn't found any information on the URL technologies.")
    if flag==1:
        f.write("####BUILTWITH OUTPUT####")
        print_log(flag,BW_response.text,f);
    print("");
    sleep(1);

    ####WHOIS####
    
    headers={
      "Accept": "application/json",
        "Authorization": "Token token=b83d3ac80ce6ac487993f5e8ade121a5"
      };
    params={
       "domain": URL
    };
    WI_response=requests.get("https://jsonwhois.com/api/v1/whois", headers=headers, params=params);
    if "error" not in WI_response.json():
        p=input("WhoIs found information about the given URL. Do you want to see them?(yes/no):");
        if p=="yes":
            print("####WHOIS OUTPUT####");
            decodedResponse = json.loads(WI_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4));
    else:
        print("WhoIs hasn't found any information on the given URL.")
    #WHOIS TUTTO COMMENTATO PER EVITARE SPRECO DI CREDITI
    if flag==1:
        f.write("####WHOIS OUTPUT####")
        print_log(flag,WI_response.text,f);
    print("");
    sleep(1);

    print("-----------------SECURITY POSTURE ANALYSIS--------------")
       ####MALTIVERSE URL####
    s=str(URL);
    hash_object = hashlib.sha256(s.encode()).hexdigest();
    MaltiverseURL_response= requests.get("https://api.maltiverse.com/url/"+hash_object );
    if 'blacklist' in MaltiverseURL_response.json():
        print("ALERT: the URL address was found through Maltiverse in at least one blacklist");
        p=input("Do you want to see the full output? (yes/no): ");
        if p=="yes":
            print("####### MALTIVERSE URL OUTPUT######");
            decodedResponse = json.loads(MaltiverseURL_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4));
        print("THE SECURITY SCORE IS DECREASING BY 20")
        SECURITY_SCORE=SECURITY_SCORE-20;
    elif 'limit' in MaltiverseURL_response.json():
        print("Maltiverse API rquest limit reached, try again in 24h");
    else:
        print("The Maltiverse search haven't produced any result")
    if flag==1:
        f.write("####MALTIVERSE URL OUTPUT####")
        print_log(flag,MaltiverseURL_response.text,f);
    print("")
    sleep(1);


    ####COIN BLOCKER LIST URL####
    CBLURL_response=requests.get("https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key=8d2082e8f770cd05fbfb82c6343638cfbee3567a&url="+urllib.parse.quote_plus(URL));
    if "error" not in CBLURL_response.json():
        if "domain_blacklist" in CBLURL_response.json()["data"]["report"]:
            if CBLURL_response.json()["data"]["report"]["domain_blacklist"]["detections"]>0:
                p=input("ALERT:According to Coin Blocker List, the given URL is maliciuos and was found in "+str(CBLURL_response.json()["data"]["report"]["blacklists"]["detections"])+" engines. Do you want to see the full output?(yes/no):")
                if p=="yes":
                    print("####COIN BLOCKER LIST URL OUTPUT####");
                    print("TUTTO COMMENTATO PER NON SPRECARE CREDITI API, EVENTUALMENTE CON 12 USD COMPRO 25000 QUERY");
                    decodedResponse = json.loads(CBLURL_response.text)
                    print(json.dumps(decodedResponse, sort_keys=True, indent=4));
                print("THE SECURITY SCORE IS DECREASING BY 20")
                SECURITY_SCORE=SECURITY_SCORE-20;
            else:
                print("Coin Blocker List hasn't found any threat related the given URL");
        else:
            print("Coin Blocker List hasn't found any threat related the given URL");
                
    else:
        print("Coin Blocker List hasn't found the given URL in any engine");
    if flag==1:
        f.write("####COIN BLOCKER LIST URL OUTPUT####")
        print_log(flag,CBLURL_response.text,f);
    print("")
    sleep(1);
    

    ####PHISHSTATS URL#####
    
    PSURL_response=requests.get("https://phishstats.info:2096/api/phishing?_where=(url,eq,"+URL+")");
    if len(PSURL_response.json())!=0:
        p=input("ALERT: According to Phishstats your URL is related to phishing threat or is dangerous,do you want to see the full output?(yes/no):");
        if p=="yes": 
            print("####PHISHSTATS URL OUTPUT####");
            decodedResponse = json.loads(PSURL_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4)); 
        print("THE SECURITY SCORE IS DECREASING BY 20")
        SECURITY_SCORE=SECURITY_SCORE-20;
    else: 
        print("Phishstats hasn't found any threat related to the given URL")
    if flag==1:
        f.write("####PHISHSTATS URL OUTPUT####")
        print_log(flag,PSURL_response.text,f);
    print("")
    sleep(1);
    

    ####GOOGLE SAFE BROWSING####
    GSB_response = SafeBrowsing("AIzaSyB-NLrsCcsDZtRPeBgawTHqNG0Ib5_pRG4")
    r =  GSB_response.lookup_urls([URL])
    if r[URL]['malicious']==True:
        print("ALERT:According to Google Safe Browsing the given URL is malicious");
        print("THE SECURITY SCORE IS DECREASING BY 30")
        SECURITY_SCORE=SECURITY_SCORE-30;
    elif r[URL]['malicious']==False:
        print("Google Safe Browsing hasn't found any threat related to the given URL");
    #print("####GOOGLE SAFE BROWSING URL OUTPUT####");
    #print(r);
    if flag==1:
        f.write("####GOOGLE SAFE BROWSING OUTPUT####")
        f.write(str(r))
    print("")
    sleep(1)
    
    
   
    #NOT SURE TO USE IT
    ####OPEN PHISH URL####
    #opdb= pyopdb.OPDB(cfg_file=<CONFIG_PATH>)
    #print(pyopdb.check_url(opdb,"http://example.com/"))
    #print(pyopdb.check_ip(opdb, "8.8.8.8"))

    ####PSBDMP####
    
    l=list(URL);
    str1="";
    if l[0]=="h" and l[1]=="t" and l[2]=="t" and l[3]=="p" and l[4]=="s" and l[5]==":"and l[6]=="/"and l[7]=="/" :
     
        l.pop(7);
        l.pop(6);
        l.pop(5);
        l.pop(4);
        l.pop(3);
        l.pop(2);
        l.pop(1);
        l.pop(0);
    elif l[0]=="h" and l[1]=="t" and l[2]=="t" and l[3]=="p" and l[4]==":" and l[5]=="/"and l[6]=="/":
      
        l.pop(6);
        l.pop(5);
        l.pop(4);
        l.pop(3);
        l.pop(2);
        l.pop(1);
        l.pop(0);
    
    PSBDMP_response=requests.get("https://psbdmp.ws/api/v3/search/"+str1.join(l));
    if PSBDMP_response.json()['count']>0:
        p=input("ALERT:PSBDMP found "+str(PSBDMP_response.json()['count'])+" elements in its Database, meaming that the given URL may be hacked. Do you want to see the full output?(yes/no):");
        if p=="yes":
            print("####PSBDMP OUTPUT####");
            decodedResponse = json.loads(PSBDMP_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4)); 
        print("THE SECURITY SCORE IS DECREASING BY 5")
        SECURITY_SCORE=SECURITY_SCORE-5;
    else:
        print("PSBDMP hasn't found anything related to the given URL");
    if flag==1:
        f.write("####PSBDMP OUTPUT####")
        print_log(flag,PSBDMP_response.text,f);
    print("");
    sleep(1);
   
    ####PHISHTANK####
    #https://worknewause.000webhostapp.com/work/login.html
    #url to try: WATCH OUT ITS A MALWARE
    headers = {
    'User-Agent': 'phishtank/vansonero',
    }
    PT_response=requests.get("http://data.phishtank.com/data/online-valid.json",headers=headers);
    PTJ=PT_response.json();
    check = URL
    flag=0
    for obj in PTJ:
        if obj.get('url') ==check :
            flag=1
    if flag==1:
        print('ALERT:According to Phishtank the given URL was found in the phishing Database');
        print("THE SECURITY SCORE IS DECREASING BY 20")
        SECURITY_SCORE=SECURITY_SCORE-20;
    elif flag==0:
        print("Phishtank hasn't found the given URL in its Phishing Database");
    if flag==1:
        f.write("####PHISHTANK OUTPUT####")
        print_log_txt_only(flag,PT_response.text,f);
    print("")
    sleep(1)
   
    ####PULSEDIVE####
    l=list(URL);
    str1="";
    if l[0]=="h" and l[1]=="t" and l[2]=="t" and l[3]=="p" and l[4]=="s" and l[5]==":"and l[6]=="/"and l[7]=="/" :
     
        l.pop(7);
        l.pop(6);
        l.pop(5);
        l.pop(4);
        l.pop(3);
        l.pop(2);
        l.pop(1);
        l.pop(0);
    elif l[0]=="h" and l[1]=="t" and l[2]=="t" and l[3]=="p" and l[4]==":" and l[5]=="/"and l[6]=="/":
      
        l.pop(6);
        l.pop(5);
        l.pop(4);
        l.pop(3);
        l.pop(2);
        l.pop(1);
        l.pop(0);
    params={
    "value": str1.join(l),
     "probe": "0",
    "pretty": "1"
    };
    
    PD_response1=requests.get("https://pulsedive.com/api/analyze.php",params=params);
    qid=PD_response1.json()['qid'];
    print("Waiting for a response from Pulsedive API, this will take 15 seconds")
    sleep(15);
    #sleep(5);#debug
    PD_response2=requests.get("https://pulsedive.com/api/analyze.php?qid="+str(qid)+"&pretty=1");
    #sleep(5);#debug
    if 'error' not in PD_response2.json():
        if PD_response2.json()["data"]["risk"]!="none":
            p=input("ALERT:According to Pulsedive the given URL is malicious with "+PD_response2.json()["data"]["risk"]+" risk. Do you want to see the full output?(yes/no):");
            if p=="yes":
                print("####PULSEDIVE OUTPUT####");
                decodedResponse = json.loads(PD_response2.text)
                print(json.dumps(decodedResponse, sort_keys=True, indent=4));
            print("THE SECURITY SCORE IS DECREASING BY 20")
            SECURITY_SCORE=SECURITY_SCORE-20;
        elif PD_response2.json()["data"]["risk"]=="none":
            print("According to Pulsedive the given URL is not malicious.");
    else :
        print("Pulsedive hasn't found any information about the given URL OR the API request failed, you may try again.");
    if flag==1:
        f.write("####PULSEDIVE OUTPUT####")
        print_log(flag,PD_response2.text,f);
    print("")
    sleep(1)    

    ####IP QUALITY SCORE URL####
    l=list(URL);
    str1="";
    if l[0]=="h" and l[1]=="t" and l[2]=="t" and l[3]=="p" and l[4]=="s" and l[5]==":"and l[6]=="/"and l[7]=="/" :
        l.pop(11);
        l.pop(10);
        l.pop(9);
        l.pop(8);
        l.pop(7);
        l.pop(6);
        l.pop(5);
        l.pop(4);
        l.pop(3);
        l.pop(2);
        l.pop(1);
        l.pop(0);
    elif l[0]=="h" and l[1]=="t" and l[2]=="t" and l[3]=="p" and l[4]==":" and l[5]=="/"and l[6]=="/":
        l.pop(10);
        l.pop(9);
        l.pop(8);
        l.pop(7);
        l.pop(6);
        l.pop(5);
        l.pop(4);
        l.pop(3);
        l.pop(2);
        l.pop(1);
        l.pop(0);
    IQSURL_response=requests.get("https://ipqualityscore.com/api/json/url/yrOKlKwtQgGpU7TlHfRjtmFeIbnUyP8t/"+str1.join(l));
    print("How to interpret the Fraud Score:");
    print("Risk Scores >= 75 - suspicious - usually due to patterns associated with malicious links.")
    print("Suspicious URLs marked with Suspicious = true will indicate domains with a high chance for being involved in abusive behavior.")
    print("Risk Scores >= 85 - high risk - strong confidence the URL is malicious.")
    print("Risk Scores = 100 AND Phishing = true OR Malware = true - indicates confirmed malware or phishing activity in the past 24-48 hours.")
    if(IQSURL_response.json()['risk_score']>=85):
        p=input("ALERT: According to IP Quality Score, the given URL is almost for sure dangerous, with a Risk Score of "+str(IQSURL_response.json()['risk_score'])+". Do you want to see the full output?(yes/no): ");
        if p=="yes":
            print("####IP QUALITY SCORE OUTPUT####");
            decodedResponse = json.loads(IQSURL_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4));
        print("THE SECURITY SCORE IS DECREASING BY 30")
        SECURITY_SCORE=SECURITY_SCORE-30;
    if(IQSURL_response.json()['risk_score']>=75 and IQSURL_response.json()['risk_score']<85):
        p=input("ALERT: According to IP Quality Score, the given URL is suspicious, with a Risk Score of "+str(IQSURL_response.json()['risk_score'])+". Do you want to see the full output?(yes/no): ");
        if p=="yes":
            print("####IP QUALITY SCORE OUTPUT####");
            decodedResponse = json.loads(IQSURL_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4));
        print("THE SECURITY SCORE IS DECREASING BY 20")
        SECURITY_SCORE=SECURITY_SCORE-20;
    if(IQSURL_response.json()['risk_score']>40 and IQSURL_response.json()['risk_score']<75):
        p=input("According to IP Quality Score, the given URL is not suspicious, with a Risk Score of "+str(IQSURL_response.json()['risk_score'])+". Do you want to see the full output?(yes/no): ");
        if p=="yes":
            print("####IP QUALITY SCORE OUTPUT####");
            decodedResponse = json.loads(IQSURL_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4));
        print("THE SECURITY SCORE IS DECREASING BY 10")
        SECURITY_SCORE=SECURITY_SCORE-10;
    if(IQSURL_response.json()['risk_score']<=40 ):
        p=input("According to IP Quality Score, the given URL is safe, with a Risk Score of "+str(IQSURL_response.json()['risk_score'])+". Do you want to see the full output?(yes/no): ");
        if p=="yes":
            print("####IP QUALITY SCORE OUTPUT####");
            decodedResponse = json.loads(IQSURL_response.text)
            print(json.dumps(decodedResponse, sort_keys=True, indent=4));
    else:
        print("IP Quality Score hasn't found anything related to the given URL")
    if flag==1:
        f.write("####IP QUALITY SCORE URL OUTPUT####")
        print_log(flag,IQSURL_response.text,f);
    print("")
    sleep(1);

    ####META DEFENDER URL####
    l=list(URL);
    str1="";
    if l[0]=="h" and l[1]=="t" and l[2]=="t" and l[3]=="p" and l[4]=="s" and l[5]==":"and l[6]=="/"and l[7]=="/" :
        l.pop(11);
        l.pop(10);
        l.pop(9);
        l.pop(8);
        l.pop(7);
        l.pop(6);
        l.pop(5);
        l.pop(4);
        l.pop(3);
        l.pop(2);
        l.pop(1);
        l.pop(0);
    elif l[0]=="h" and l[1]=="t" and l[2]=="t" and l[3]=="p" and l[4]==":" and l[5]=="/"and l[6]=="/":
        l.pop(10);
        l.pop(9);
        l.pop(8);
        l.pop(7);
        l.pop(6);
        l.pop(5);
        l.pop(4);
        l.pop(3);
        l.pop(2);
        l.pop(1);
        l.pop(0);
    #url = "https://api.metadefender.com/v4/domain/"+str1.join(l);
    url = "https://api.metadefender.com/v4/url/"+urllib.parse.quote_plus(URL);
    headers = {
    "apikey": "909b1815323adff03705bd8b905fefb0"
    }
    MDURL_response = requests.request("GET", url, headers=headers);
    #MDURL_response=requests.get("https://api.metadefender.com/v4/url/"+URL,headers=headers)
    print("How to interpret the status:");
    print("0	Allowlisted: URL is listed by the source in their allowlist. Note: Not all sources provide allowlists.");
    print("1	Blocklisted: URL is listed by the source in their blocklist. Refer to the source for more information regarding their blocklist.")
    print("3	Failed to scan: The results could not be retrieved from our servers")
    print("5	Unknown: The source has not listed this URL address in either their blocklist or allowlist.")
    
    if "lookup_results" in MDURL_response.json():
        if MDURL_response.json()["lookup_results"]["detected_by"]>0:
            count=0;
            for source in MDURL_response.json()["lookup_results"]["sources"]:
                if source["status"]==1:
                    count=count+1;
            if count>0 :
                p=input("ALERT: According to Meta Defenfer, the given URL was found in: "+str(count)+" Blocklist. Do you want to see the full output?(yes/no):")
                if p=="yes": 
                    print("#### META DEFENDER URL OUTPUT####")
                    decodedResponse = json.loads(MDURL_response.text)
                    print(json.dumps(decodedResponse, sort_keys=True, indent=4));
                print("THE SECURITY SCORE IS DECREASING BY 20")
                SECURITY_SCORE=SECURITY_SCORE-20;
            else: 
                p=input("According to Meta Defender, the given URL wasn't found in any Blocklist. Do you want to see the full output?(yes/no):")
                if p=="yes": 
                    print("#### META DEFENDER URL OUTPUT####")
                    decodedResponse = json.loads(MDURL_response.text)
                    print(json.dumps(decodedResponse, sort_keys=True, indent=4));
        else:
            print("Meta Defender wasn't able to find anything related to the given URL");
    else:
        print("Meta Defender wasn't able to find anything related to the given URL");
    if flag==1:
        f.write("####META DEFENDER URL OUTPUT####")
        print_log(flag,MDURL_response.text,f);
    print("")
    sleep(1);
    print("")
    print("---------------------------SECURITY SCORE RESULTS---------------------------")
    print("")
    print("")
    if SECURITY_SCORE==100 :
        print("The Security Score of the given URL is "+str(SECURITY_SCORE))
        print("It means that, according to all the blacklists and sources implemented in this Tool, the given URL is safe and not malicious.")
        print("CAUTION: this is Tool provides a good indicator of security, BUT this doesn't mean that the given URL is for sure safe. Other analysis may be required ")
    elif SECURITY_SCORE==95:
        print("The Security Score of the given URL is "+str(SECURITY_SCORE))
        print("According to the sources in this tool, the given URL is not related to any threat, but has been found in a leaks database, meaning some information may have been leaked from that URL")
    elif SECURITY_SCORE>=75 and SECURITY_SCORE<95:
        print("The Security Score of the given URL is "+str(SECURITY_SCORE))
        print("It means that the given URL was found in one ( or maximum two) blacklist or tool, meaning that it may be malicious.")
    elif SECURITY_SCORE>=45 and SECURITY_SCORE<75:
        print("The Security Score of the given URL is "+str(SECURITY_SCORE))
        print("It means that the given URL was found in more blacklists and tool, indicating that it is probably malicious and related to a threat.")
    elif SECURITY_SCORE<40:
        if SECURITY_SCORE < 0 :
            SECURITY_SCORE=0;
        print("The Security Score of the given URL is "+str(SECURITY_SCORE))
        print("It means that the given URL was found in multiple blacklists and tools, meaning that it is for sure malicious and related to a threat.")

    print("")
    print("Thank you for using this Tool   -Alessandro Vannini")
    print("-----------------------------------------------------------------------------")
    if flag==1:
        f.close()

    

def print_log(flag,texts,f):
    if flag==1:
        decodedResponse = json.loads(texts)
        f.write(json.dumps(decodedResponse, sort_keys=True, indent=4));

def print_log_txt_only(flag,texts,f):
    if flag==1:
        f.write(texts);



if __name__ == "__main__":
    main()