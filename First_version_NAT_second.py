from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.ofproto import ether
import IPy

class NAPT_Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NAPT_Controller, self).__init__(*args, **kwargs)
        self.ip_intranet = IPy.IP('192.168.0.0/24')
        self.ip_extranet = IPy.IP('192.168.1.0/24')
        #Mac address table
        self.mac_to_port = { }
        self.ip_to_mac = { }
        self.original_ip_to_id = { }
        self.original_ip_to_port = { }
        self.icmp_table = { }
        self.tcp_table ={}
        self.icmp_reverse_table ={ }
        self.tcp_reverse_table = { }
        self.id_number = 1
        self.port_number = 1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self,ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow_entry(datapath, 0, match, actions)

    def add_flow_entry(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instr = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority = priority, match = match ,instructions = instr)
        datapath.send_msg(mod)

    #behavior of the switch
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def switch_packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
       # The Id of the switch
        datapath_id = datapath.id
        self.mac_to_port.setdefault(datapath_id,{})
        if datapath_id != 1:
            return

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt.ethertype ==ether.ETH_TYPE_LLDP:
            return
        dst = eth_pkt.dst
        src = eth_pkt.src

        #which port of the switch that the message comes from
        in_port = msg.match['in_port']
        self.logger.info("packet in %s %s %s %s", datapath_id, src, dst, in_port)
        self.mac_to_port[datapath_id][src] = in_port

        # if the mapping between port and MAC has been created,sent the frame to the corresponding port,otherwise flood
        if dst in self.mac_to_port[datapath_id]:
            out_port = self.mac_to_port[datapath_id][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        #add a flow into the switch ,then next time message comes in with learned port can be set forward to the next hop
        #without been sent to the controller

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port =in_port, eth_dst = dst)
            self.add_flow_entry(datapath,1, match,actions)

        out= parser.OFPPacketOut(datapath = datapath, buffer_id = ofproto.OFP_NO_BUFFER, in_port = in_port,
                                 actions =actions, data=msg.data)
        datapath.send_msg(out)



    # behavior of the router
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def router_packet_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        datapath_id = datapath.id
        if datapath_id != 2:
            return

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if(ipv4_pkt and (ipv4_pkt.dst in self.ip_intranet) and (ipv4_pkt.src in self.ip_intranet)):
            return
        if (arp_pkt):
            if (arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip in self.ip_intranet):
                return

            else:

                self.arp__packet_handler(datapath,eth_pkt,arp_pkt)
                return

        if (icmp_pkt):
            self.icmp_packet_handler(datapath,ipv4_pkt,icmp_pkt)

        if(tcp_pkt):
            self.tcp_packet_handler(datapath,datapath_id,eth_pkt,ipv4_pkt,tcp_pkt)

    def tcp_packet_handler(self, datapath, datapath_id, eth_pkt, ipv4_pkt, tcp_pkt ):
        # recrord the mapping relation between the orginal source ip address and source port
        if ipv4_pkt.src not in self.tcp_table:
            self.tcp_table[ipv4_pkt.src]=self.port_number
            self.tcp_reverse_table[self.port_number] = ipv4_pkt.src
            self.port_number += 1
        # recrords the mapping relation between the orginal source ip address and the source port after NAT
        if ipv4_pkt.src not in self.original_ip_to_port:
            self.original_ip_to_port[ipv4_pkt.src] = tcp_pkt.src_port
        #  modify the source ip address and source port of the tcp ,send it tho the extranet
        if ipv4_pkt.src in self.ip_intranet:
            nat_eth_pkt = ethernet.ethernet(ethertype=ether.ETH_TYPE_IP,
                                        dst=self.ip_to_mac[ipv4_pkt.dst],
                                        src=datapath.ports[2].hw_addr)
            nat_tcp_pkt = tcp.tcp(src_port=self.tcp_table[ipv4_pkt.src],
                                  dst_port=tcp_pkt.dst_port,
                                  seq=tcp_pkt.seq,
                                  ack=tcp_pkt.ack,
                                  offset=0,
                                  bits=tcp_pkt.bits,
                                  window_size=tcp_pkt.window_size,
                                  csum=0,
                                  urgent=tcp_pkt.urgent,
                                  option=tcp_pkt.option,
                                  )
            ipv4_pkt.src = '192.168.1.0'
            tcp_nat_pkt = packet.Packet()
            tcp_nat_pkt.add_protocol(nat_eth_pkt)
            tcp_nat_pkt.add_protocol(ipv4_pkt)
            tcp_nat_pkt.add_protocol(nat_tcp_pkt)
            self.send_packet(datapath, 2, tcp_nat_pkt)
            return
        #  Based on the mapping relation created before,find the origal ip and source port,
        #  modify the source ip address and source of the tcp packet ,send it to the intranet
        if ipv4_pkt.src in self.ip_extranet:
            self.logger.info("the sdasdasdasd port number is %s", tcp_pkt.dst_port)
            orignal_ip = self.tcp_reverse_table[tcp_pkt.dst_port]
            orginal_port = self.original_ip_to_port[orignal_ip]
            nat_eth_pkt = ethernet.ethernet(ethertype=ether.ETH_TYPE_IP,
                                        dst=self.ip_to_mac[orignal_ip],
                                        src=datapath.ports[1].hw_addr)
            nat_tcp_pkt = tcp.tcp(src_port=tcp_pkt.src_port,
                                  dst_port=orginal_port,
                                  seq=tcp_pkt.seq,
                                  ack=tcp_pkt.ack,
                                  offset=0,
                                  bits=tcp_pkt.bits,
                                  window_size=tcp_pkt.window_size,
                                  csum=0,
                                  urgent=tcp_pkt.urgent,
                                  option=tcp_pkt.option,
                                  )
            ipv4_pkt.dst = orignal_ip
            tcp_nat_pkt = packet.Packet()
            tcp_nat_pkt.add_protocol(nat_eth_pkt)
            tcp_nat_pkt.add_protocol(ipv4_pkt)
            tcp_nat_pkt.add_protocol(nat_tcp_pkt)
            self.send_packet(datapath, 1, tcp_nat_pkt)
            return




    def icmp_packet_handler(self,datapath, ipv4_pkt,icmp_pkt) :
        #recrord the mapping relation between the orginal source ip address and id
        if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
            if ipv4_pkt.src not in self.icmp_table:
                self.icmp_table[ipv4_pkt.src] = self.id_number
                self.icmp_reverse_table[self.id_number] = ipv4_pkt.src
                self.id_number += 1

            # recrords the mapping relation between the orginal source ip address and the id after NAT
            self.original_ip_to_id[ipv4_pkt.src] =icmp_pkt.data.id

            #  modify the source ip address and id of the icmp_echo_request ,send it tho the extranet
            nat_eth_pkt = ethernet.ethernet(ethertype = ether.ETH_TYPE_IP,
                                          dst = self.ip_to_mac[ipv4_pkt.dst],
                                          src = datapath.ports[2].hw_addr)
            nat_icmp__echo_pkt = icmp.echo(id_ = self.icmp_table[ipv4_pkt.src],
                                     seq = icmp_pkt.data.seq,
                                     data = icmp_pkt.data.data,
                                     )
            nat_icmp_pkt = icmp.icmp(type_ = icmp_pkt.type,
                                     code = icmp_pkt.code,
                                     csum = 0,
                                     data = nat_icmp__echo_pkt
                                     )
            ipv4_pkt.src = '192.168.1.0'
            icmp_nat_pkt = packet.Packet()
            icmp_nat_pkt.add_protocol(nat_eth_pkt)
            icmp_nat_pkt.add_protocol(ipv4_pkt)
            icmp_nat_pkt.add_protocol(nat_icmp_pkt)
            self.send_packet(datapath,2,icmp_nat_pkt)
            return
        #  Based on the mapping relation created before,find the origal ip and id,
        #  modify the source ip address and id of the icmp_echo_reply ,send it to the intranet
        if icmp_pkt.type == icmp.ICMP_ECHO_REPLY:
            orignal_ip = self.icmp_reverse_table[icmp_pkt.data.id]
            orignal_id = self.original_ip_to_id[orignal_ip]
            nat_eth_pkt = ethernet.ethernet(ethertype = ether.ETH_TYPE_IP,
                                          dst = self.ip_to_mac[orignal_ip],
                                          src = datapath.ports[1].hw_addr)
            nat_icmp__reply_pkt = icmp.echo(id_ = orignal_id,
                                     seq = icmp_pkt.data.seq,
                                     data = icmp_pkt.data.data,
                                     )
            nat_icmp_pkt = icmp.icmp(type_ = icmp_pkt.type,
                                     code = icmp_pkt.code,
                                     csum = 0,
                                     data = nat_icmp__reply_pkt
                                     )
            ipv4_pkt.dst = orignal_ip
            icmp_nat_pkt = packet.Packet()
            icmp_nat_pkt.add_protocol(nat_eth_pkt)
            icmp_nat_pkt.add_protocol(ipv4_pkt)
            icmp_nat_pkt.add_protocol(nat_icmp_pkt)
            self.send_packet(datapath,1, icmp_nat_pkt)
            return


    def arp__packet_handler(self,datapath,datapath_id, arp_pkt):
        # record the mapping relation between the ip and mac address
        if arp_pkt.src_ip not in self.ip_to_mac:
            self.ip_to_mac[arp_pkt.src_ip] = arp_pkt.src_mac

        if arp_pkt.opcode == arp.ARP_REQUEST:
            if arp_pkt.src_ip in self.ip_intranet:
                # Create an arp_ reply packet and send it back to the sender
                arp_reply = packet.Packet()
                reply_eth_pkt = ethernet.ethernet(ethertype = ether.ETH_TYPE_ARP,
                                                  dst = arp_pkt.src_mac,
                                                  src = datapath.ports[1].hw_addr)

                reply_arp_pkt = arp.arp( opcode = arp.ARP_REPLY,
                                        src_mac = datapath.ports[1].hw_addr,
                                        src_ip = arp_pkt.dst_ip,
                                        dst_mac = arp_pkt.src_mac,
                                        dst_ip = arp_pkt.src_ip)

                arp_reply.add_protocol(reply_eth_pkt)
                arp_reply.add_protocol(reply_arp_pkt)
                self.send_packet(datapath,1, arp_reply)

                arp_request = packet.Packet()
                request_eth_pkt = ethernet.ethernet(ethertype = ether.ETH_TYPE_ARP,
                                                    dst='ff:ff:ff:ff:ff:ff',
                                                    src= datapath.ports[2].hw_addr )

                request_arp_pkt = arp.arp(opcode = arp.ARP_REQUEST,
                                          dst_ip = arp_pkt.dst_ip,
                                          dst_mac = '00:00:00:00:00:00',
                                          src_ip = '192.168.1.0',
                                          src_mac = datapath.ports[2].hw_addr)
                arp_request.add_protocol(request_eth_pkt)
                arp_request.add_protocol(request_arp_pkt)
                self.send_packet(datapath,2, arp_request)
                return
            # Create an arp_ request packet and send it to the extranet
            if arp_pkt.src_ip in self.ip_extranet:
                arp_reply = packet.Packet()
                reply_eth_pkt = ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                                  dst=arp_pkt.src_mac,
                                                  src=datapath.ports[2].hw_addr)

                reply_arp_pkt = arp.arp(opcode=arp.ARP_REPLY,
                                        src_mac=datapath.ports[2].hw_addr,
                                        src_ip=arp_pkt.dst_ip,
                                        dst_mac=arp_pkt.src_mac,
                                        dst_ip=arp_pkt.src_ip)

                arp_reply.add_protocol(reply_eth_pkt)
                arp_reply.add_protocol(reply_arp_pkt)
                self.send_packet(datapath, 2, arp_reply)
                return

        if arp_pkt.opcode == arp.ARP_REPLY:
            return


    def send_packet(self,datapath,port,pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port)]

        out =parser.OFPPacketOut(datapath = datapath, buffer_id = ofproto.OFP_NO_BUFFER,
                                 in_port = ofproto.OFPP_CONTROLLER,actions = actions,data = data)
        datapath.send_msg(out)


















