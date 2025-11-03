from scapy.all import sniff

def mostrar_pacote(pacote):
    print(pacote.summary())
    if pacote.haslayer('Raw'):
        try:
            print(pacote['Raw'].load.decode('utf-8', errors='ignore'))
        except Exception as e:
            print(pacote['Raw'].load)

        print("-" * 50)

sniff(prn=mostrar_pacote, filter="tcp", store=False)