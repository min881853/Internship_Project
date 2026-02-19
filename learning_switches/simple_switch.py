#simple_switch.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from switch_features_handler import SwitchFeaturesHandler
from packet_in_handler import PacketInHandler
from firewall_handler import FirewallHandler

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.firewall = FirewallHandler(self.logger, './sdn_module/firewall_rule.txt')
        self.switch_features_handler = SwitchFeaturesHandler(self.logger)
        self.packet_in_handler = PacketInHandler(self.logger, self.mac_to_port, self.firewall)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler_wrapper(self, ev):
    	self.switch_features_handler.handle_switch_features(ev.msg.datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler_wrapper(self, ev):
        self.packet_in_handler.handle_packet_in(ev.msg)

