from abc import ABC, abstractmethod

from scapy.all import IP, Ether, Packet, wrpcap, rdpcap

import os

from fip.ssh import SSH

class PacketProcessed(ABC):
    def __init__(self, file: str, packets: list[Packet]) -> None:
        self.file = file
        self.packets = packets
    def __getitem__(self, i):
        return self.__dict__[i]


class PacketProcessor(ABC):
    def __init__(self, dir: str, file_extension="pcap") -> None:
        assert os.path.exists(dir)

        self.dir = dir
        self.files = []
        if os.path.isdir(dir):
            self.__get_filenames(file_extension)
        elif os.path.isfile(dir):
            self.files = [dir]

    def __get_filenames(self, file_extension) -> None:
        for filename in os.listdir(self.dir):
            if filename.endswith(f'.{file_extension}'):
                file = os.path.join(self.dir, filename)
                self.files.append(file)

    def __enter__(self):
        return self

    def __iter__(self):
        return self

    def next(self) -> PacketProcessed:
        """
        implement the iterator protocol on a set of packets in a pcap file
        """
        try:
            file = self.files.pop(0)
            return PacketProcessed(os.path.basename(file), self.read_packet(file))
        except IndexError:
            raise StopIteration

    __next__ = next

    def write_packet(self) -> None:
        wrpcap(f'{self.filename}_converted.pcap', self.packets, append=True)

    def read_packet(self, file) -> str:
        pcap = rdpcap(filename=file)
        packets = []
        for pkt in pcap:
            processed_packet = self.preprocessing(pkt)
            if processed_packet != None:
                packets.append(processed_packet)
        return packets

    @abstractmethod
    def preprocessing(self, packet: Packet) -> Packet:
        pass

    def __exit__(self, exc_type, exc_value, tracback) -> None:
        pass


class HTTPPacketProcessor(PacketProcessor):
    def __init__(self, dir) -> None:
        PacketProcessor.__init__(self, dir)

    def preprocessing(self, packet: Packet)-> Packet:
        processed_packet = packet
        #if processed_packet.haslayer(Ether):
        #    processed_packet[Ether].src = "00:00:00:00:00:00"
        #    processed_packet[Ether].dst = "00:00:00:00:00:00"

        #if processed_packet.haslayer(IP):
        #    processed_packet[IP].src = "0.0.0.0"
        #    processed_packet[IP].dst = "0.0.0.0"

        return processed_packet

    def __enter__(self):
        return self


class SSHPacketProcessor(PacketProcessor):
    def __init__(self, dir) -> None:
        PacketProcessor.__init__(self, dir)

    def preprocessing(self, packet: Packet)-> Packet:
        processed_packet = packet
        #if processed_packet.haslayer(Ether):
        #    processed_packet[Ether].src = "00:00:00:00:00:00"
        #    processed_packet[Ether].dst = "00:00:00:00:00:00"

        #if processed_packet.haslayer(IP):
        #    processed_packet[IP].src = "0.0.0.0"
        #    processed_packet[IP].dst = "0.0.0.0"

        #if processed_packet.haslayer(SSH):
        #    processed_packet = processed_packet[SSH]

        return processed_packet

    def __enter__(self):
        return self
