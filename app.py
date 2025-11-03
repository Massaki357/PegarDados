from scapy.all import sniff, wrpcap

def process_packet(pkt):
    print(pkt.summary())


def validar_protocolo(protocolo):
    protocolos_validos = ['tcp', 'udp']
    if protocolo in protocolos_validos:
        return True
    return False

if __name__ == "__main__":
    print("Iniciando captura... Pressione Ctrl+C para parar.")
    protocolo = input("Digite o protocolo a ser capturado (tcp/udp): ").strip().lower()

    while validar_protocolo(protocolo) == False:
        print("Protocolo inválido. Tente novamente.")
        protocolo = input("Digite o protocolo a ser capturado (tcp/udp): ").strip().lower()

    packets = sniff(prn=process_packet, store=True, filter=f"{protocolo}")
    wrpcap("captura.pcap", packets)
